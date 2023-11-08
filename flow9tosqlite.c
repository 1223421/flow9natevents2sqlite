#include <sys/stat.h>
#include <libgen.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include "sqlite3.h"

uint8_t * long2ip(unsigned int ip, short addzero) {
        uint8_t *result = (uint8_t*) malloc(sizeof (uint8_t) * 15);
        if(ip==0) {
                return "000.000.000.000";
        }
	uint8_t ip_[4];
        ip_[0] = ip >> 24;ip_[1] = ip >> 16;ip_[2] = ip >> 8;ip_[3] = ip;
        int fdop = 0;
        if(ip_[0]<10) fdop++;if(ip_[0]<100) fdop++;
        if(ip_[1]<10) fdop++;if(ip_[1]<100) fdop++;
        if(ip_[2]<10) fdop++;if(ip_[2]<100) fdop++;
        if(ip_[3]<10) fdop++;if(ip_[3]<100) fdop++;

        struct in_addr clientip_ = {ntohl(ip)};

        uint8_t dop[fdop];
        for(int i=0;i<fdop;i++) {
                dop[i] = 33;
        }
	if(addzero==1) {
                sprintf(result, "%.3u.%.3u.%.3u.%.3u", ip_[0], ip_[1], ip_[2], ip_[3]);
        } else {
                sprintf(result, "%u.%u.%u.%u", ip_[0], ip_[1], ip_[2], ip_[3]);
        }
	return result;
}

#pragma pack(push, 1)
struct base_recv {
        uint16_t version;
        uint16_t countflows;
        uint32_t sysuptime;
        uint32_t unixtime;
        uint32_t flowsequence;
        uint32_t sourceid;
        uint8_t flows[1500];
};
struct flow_ {
        uint64_t timestamp;
        uint32_t srcip;
        uint32_t dstip;
        uint32_t pnatsrc;
        uint32_t pnatdst;
        uint16_t srcport;
        uint16_t dstport;
        uint16_t pnatsrcport;
        uint16_t pnatdstport;
        uint8_t protocol;
        uint8_t event;
};
#pragma pack(pop)
#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))

int main(int argc, char * argv[]) {
	char sqlitefile[255];
	int sqlopend = 0;
	sqlite3 *dbsqlite;
	const char* SQL_TABLE = "CREATE TABLE IF NOT EXISTS nat_logs(start datetime, end datetime, srcip int unsigned, psrcip int unsigned, dstip int unsigned, pdstip int unsigned, sport int, psport int, dport int, pdport int, protocol int);";

	char dir_[255];
	sprintf(dir_, "%s", dirname(argv[0]));

	FILE *mf;
        char filename[255];
        sprintf(filename, "%s/flow9.pid", dir_);
        char fb_d[255];

        sprintf(fb_d, "%s/tmpfs/nat_logs/", dir_);
        mkdir(fb_d, 0777);

        if(mf=fopen(filename,"r")) {
                char cpid[25];
                fgets(cpid, 25, mf);
                pid_t rpid = atoi(cpid);
                int result = kill(rpid, 0);
                if(result==0) {
                        fprintf(stderr, "Уже запущена копия процесса\n");
                        fflush(stderr);
			exit(0);
                }
        }

        mf=fopen (filename,"w");
        fprintf(mf, "%d", getpid());
        fflush(mf);
        fclose (mf);

        int s;
        if((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
                fprintf(stderr, "socket creation failed");
		fflush(stderr);
                exit(0);
        }
	int debug = 0;
	if(!argv[1] || !argv[2]) {
		fprintf(stdout, "нужно 2 параметра: адрес и порт на который биндится.\n");
		fflush(stdout);
		exit(0);
	}
	if(argv[3]) {
		debug = 1;
	}

        int opt = 1;
        int ru = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in servaddr, cliaddr, aaddr;
        servaddr.sin_family    = AF_INET;
        servaddr.sin_addr.s_addr = inet_addr(argv[1]);

        servaddr.sin_port = htons(atoi(argv[2]));
        if(bind(s, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
                fprintf(stderr, "socket bind failed");
		fflush(stderr);
                exit(0);
        }
        char buffer[1500];
        int len, n;
        len = sizeof(cliaddr);

        struct base_recv *b;
        struct flow_ *f;
	b = (struct base_recv*)malloc(sizeof(struct base_recv));
	f = (struct flow_*)malloc(sizeof(struct flow_));
	char fb_[255];

	int nat_id_flow = -1;

	sprintf(fb_, "%s/now_id", dir_);
	if(mf=fopen (fb_, "r")) {
		char str[1024];
		bzero(str, 1024);
		fgets(str, 1024, mf);
		if(atoi(str)>0) nat_id_flow = atoi(str);
		fclose(mf);
	}
	if(debug) {
		fprintf(stdout, "Предыдущий id natevents из файла now_id: %d (после ребута сервера/модуля лучше удалять файл)\n", nat_id_flow);
		fflush(stdout);
	}
        while(1) {
                n = recvfrom(s, (char *)buffer, 1500,
                        MSG_WAITALL, ( struct sockaddr *) &cliaddr,
                        (socklen_t *)&len);

		if(n<=0 || len<=0) {
			continue;
		}

		b = (struct base_recv*) buffer;

		unsigned int sizeflowset_;
		unsigned int idflowset_;
		unsigned int id_ = 0;
		uint8_t flowset[1500];
		uint8_t flow[1500];
		while(id_<n-20) {
			idflowset_ = b->flows[id_] << 8 | b->flows[id_+1];
			sizeflowset_ = b->flows[id_+2] << 8 | b->flows[id_+3];
			if(idflowset_==0) { //template
				short tid = b->flows[id_+4] << 8 | b->flows[id_+5];
				short field_count = b->flows[id_+6] << 8 | b->flows[id_+7];
				short type_first = b->flows[id_+8] << 8 | b->flows[id_+9];
				if(field_count==11 && type_first==323) { //nat_events
					if(nat_id_flow!=tid) {
						nat_id_flow = tid;
						sprintf(fb_, "%s/now_id", dir_);
						if(mf=fopen (fb_, "w")) {
							fprintf(mf, "%u", tid);
							fflush(mf);
							fclose(mf);
						}
						if(debug) {
							fprintf(stdout, "Изменился id natevents на %d\n", nat_id_flow);
							fflush(stdout);
						}
					}
				}
			}
			if(idflowset_==nat_id_flow) { //eventsnat
				int j = 0;
				for(int i = 0;i<sizeflowset_-4; i++) {
					flowset[i] = b->flows[id_+4+i];
					flow[j] = b->flows[id_+4+i];
					j++;
					if(j==34) {
						j=0;
						f = (struct flow_*) flow;
						unsigned int srcip = htonl(f->srcip);
						unsigned int dstip = htonl(f->dstip);
						unsigned int pnatsrcip = ntohl(f->pnatsrc);
						unsigned int pnatdstip = htonl(f->pnatdst);
						int sport = htons(f->srcport);
						int dport = htons(f->dstport);
						int pnatsport = htons(f->pnatsrcport);
						int pnatdport = htons(f->pnatdstport);
						int proto = f->protocol;
						uint64_t time_ = htonll(f->timestamp);

						time_t now = time_/1000;
						struct tm ts = *localtime(&now);
						int msec = time_ % 1000;
						char datetime[50];
						strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", &ts);
						sprintf(datetime, "%s.%d", datetime, msec);
						if(f->event==1) {
							sprintf(fb_, "%s/tmpfs/nat_logs/%u_%u_%u_%u_%hu_%hu_%hu_%hu_%u", dir_, srcip, pnatsrcip, dstip, pnatdstip, sport, pnatsport, dport, pnatdport, proto);
							if(mf=fopen (fb_, "w")) {
								fprintf(mf, "%lu", now);
								fflush(mf);
								fclose(mf);
							}
							if(debug) {
								fprintf(stdout, "%s: create: %s:%d(%s:%d) -> %s:%d(%s:%d) %u\n", datetime, long2ip(srcip, 0), sport, long2ip(pnatsrcip, 0), pnatsport, long2ip(dstip, 0), dport, long2ip(pnatdstip, 0), pnatdport, f->protocol);
								fflush(stdout);
							}
						} else if(f->event==2) {
							sprintf(fb_, "%s/tmpfs/nat_logs/%u_%u_%u_%u_%hu_%hu_%hu_%hu_%u", dir_, srcip, pnatsrcip, dstip, pnatdstip, sport, pnatsport, dport, pnatdport, proto);
							unsigned long int start_ = 0;
							if (access(fb_, F_OK) == 0) {
								if(mf=fopen (fb_, "r")) {
									char str[1024];
									bzero(str, 1024);
									fgets(str, 1024, mf);
									if(atoi(str)>0) start_ = atol(str);
									fclose(mf);
								}
								sprintf(fb_d, "%s/nat_logs/%d/%02d", dir_, ts.tm_year + 1900, ts.tm_mon + 1);
								if (access(fb_d, F_OK) != 0) {
									sprintf(fb_d, "%s/nat_logs", dir_);
									mkdir(fb_d, 0777);
									sprintf(fb_d, "%s/nat_logs/%d", dir_, ts.tm_year + 1900);
									mkdir(fb_d, 0777);
									sprintf(fb_d, "%s/nat_logs/%d/%02d", dir_, ts.tm_year + 1900, ts.tm_mon + 1);
									mkdir(fb_d, 0777);
								}
								char sqlitefile_[255];
								sprintf(sqlitefile_, "%s/nat_logs/%d/%02d/%02d.db", dir_, ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday);
								if(strcmp(sqlitefile_, sqlitefile)!=0) {
									sprintf(sqlitefile, "%s/nat_logs/%d/%02d/%02d.db", dir_, ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday);
									if(sqlopend==1) {
										sqlite3_close(dbsqlite);
									}
									sqlopend = 1;
									sqlite3_open(sqlitefile, &dbsqlite);
									char * err;
									sqlite3_exec(dbsqlite, SQL_TABLE, 0, 0, &err);
								}
								sprintf(fb_d, "%s/nat_logs/%d/%02d/%02d/%s", dir_,
								ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday, long2ip(dstip, 0));
								remove(fb_);
							} else start_ = 0;
							if(start_>0) {
								if(sqlopend==1) {
									char SQL[1024];
									sprintf(SQL, "insert into `nat_logs` VALUES(DATETIME(DATETIME('%lu', 'unixepoch'), 'localtime'), DATETIME(DATETIME('%lu', 'unixepoch'), 'localtime'), '%u', '%u', '%u', %u, '%hu', '%hu', '%hu', '%hu', '%u');",
									start_, now, srcip, pnatsrcip, dstip, pnatdstip, sport, pnatsport, dport, pnatdport, proto);
									char * err;
									sqlite3_exec(dbsqlite, SQL, 0, 0, &err);
								}
							}
							if(debug) {
								fprintf(stdout, "%s: delete: %s:%d(%s:%d) -> %s:%d(%s:%d) %u\n", datetime, long2ip(srcip, 0), sport, long2ip(pnatsrcip, 0), pnatsport, long2ip(dstip, 0), dport, long2ip(pnatdstip, 0), pnatdport, f->protocol);
								fflush(stdout);
							}
						}
					}
				}
			}
			id_ = id_+sizeflowset_;
		}
		continue;
        }
	return 0;
}
