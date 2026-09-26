#define _POSIX_C_SOURCE 200809L
#include "orbit_posix.h"
#include "client.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char**argv){orbit_posix_t platform;orbit_client_services_t services;if(argc!=2){fputs("usage: orbit_pi /private/storage/directory\n",stderr);return 2;}int dir=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(dir<0)return 2;int32_t status=orbit_posix_open(&platform,dir,&services);close(dir);if(status)return 2;status=orbit_example_start(&services);if(!status)status=orbit_example_tick();if(status==ORBIT_CLIENT_ACTIVATION_REQUIRED||status==ORBIT_CLIENT_PENDING){char key[258];fputs("Licence key (input is not stored; use a private terminal): ",stderr);if(!fgets(key,sizeof(key),stdin)){orbit_posix_close(&platform);return 2;}size_t n=strcspn(key,"\r\n");status=n&&n<=256?orbit_example_activate((uint8_t*)key,(uint32_t)n):ORBIT_CLIENT_ARGUMENT;volatile char*p=key;for(size_t i=0;i<sizeof(key);++i)p[i]=0;}if(!status)status=orbit_example_check();puts(status==0?"Export access allowed":"Export access unavailable");orbit_posix_close(&platform);return status?1:0;}
