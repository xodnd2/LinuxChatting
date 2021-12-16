/*
* Author:  Arjun Sreedharan
* License: GPL version 2 or higher http://www.gnu.org/licenses/gpl.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <arpa/inet.h>

#define BUFF_SIZE 256
#define USERNAME_MAX_SIZE 20

static char username[USERNAME_MAX_SIZE];

pthread_cond_t console_cv;
pthread_mutex_t console_cv_lock;

void error(void)
{
	fprintf(stderr, "%s\n", "bad command\n"
		"Type 'help' to see the lists of commands.");
}

void console(int sockfd)
{
	char buffer[BUFF_SIZE];
	char *recipient, *msg, *tmp;

	memset(buffer, 0, sizeof buffer);
	printf("%s\n%s\n", 
		"Welcome to chat client console. Please enter commands",
		"Type 'help' to see the lists of commands.");

	while(1) {
		printf("[%s]$ ", username);
		fgets(buffer, sizeof buffer, stdin);
		/* fgets also reads the \n from stdin, strip it */
		buffer[strlen(buffer) - 1] = '\0';

		if(strcmp(buffer, "") == 0)
			continue;

		if(strncmp(buffer, "exit", 4) == 0) {
			write(sockfd, "exit", 6);
			
			pthread_mutex_destroy(&console_cv_lock);
			pthread_cond_destroy(&console_cv);
			_exit(EXIT_SUCCESS);
		}
		if(strncmp(buffer, "help", 2) == 0) {
			printf("%s%s%s%s\n\n",
			"\nls : show list of members",
			"\nsend [username] [message] : send message to specific user",
			"\nall [message] : send message to all",
			"\nexit : end process");
			continue;
		}

		if(strncmp(buffer, "ls", 2) == 0) {

			pthread_mutex_lock(&console_cv_lock);
			write(sockfd, "ls", 2);
			pthread_cond_wait(&console_cv, &console_cv_lock);
			pthread_mutex_unlock(&console_cv_lock);
			continue;
		}

		/* `send <recipient> <msg>` sends <msg> to the given <username> */
		if(strncmp(buffer, "send ", 5) == 0) {
			/* the following is to validate the syntax */
			tmp = strchr(buffer, ' ');
			if(tmp == NULL) {
				error();
				continue;
			}
			recipient = tmp + 1;

			tmp = strchr(recipient, ' ');
			if(tmp == NULL) {
				error();
				continue;
			}
			msg = tmp + 1;

			/* issue the `send` command to server */
			write(sockfd, buffer, 5 + strlen(recipient) + 1 + strlen(msg) + 1);
			continue;
		}
		
		if(strncmp(buffer, "all ", 4) == 0) {
			/* the following is to validate the syntax */
			tmp = strchr(buffer, ' ');
			if(tmp == NULL) {
				error();
				continue;
			}
			msg = tmp + 1;

			/* issue the `send` command to server */
			write(sockfd, buffer, 4 + strlen(msg) + 1);
			continue;
		}
		error();
	}
}


void register_username(int sockfd)
{
	char *regstring = malloc(USERNAME_MAX_SIZE + 18);
	sprintf(regstring, "register username %s", username);
	write(sockfd, regstring, strlen(regstring));
	free(regstring);
}


void *receiver(void *sfd)
{
	char buffer[BUFF_SIZE] = {0};
	int sockfd = *(int*)sfd;
	int readlen;

	while(1) {
		memset(buffer, 0, sizeof buffer);
		readlen = read(sockfd, buffer, sizeof buffer);
		if(readlen < 1)
			continue;
		pthread_mutex_lock(&console_cv_lock);
		printf("%s\n", buffer);

		pthread_cond_signal(&console_cv);
		pthread_mutex_unlock(&console_cv_lock);
	}
}

int main(int argc, char * argv[])
{
	if(argc != 3)
	{
		printf("Usage : ./filename [IP] [PORT] \n");
		exit(0);
	}
	char *IP = argv[1];
	in_port_t PORT = atoi(argv[2]);
	int sockfd;

	struct sockaddr_in serv_addr;

	/* just to dump the handle for the spawned thread - no use */
	pthread_t receiver_thread;

	pthread_cond_init(&console_cv, NULL);
	pthread_mutex_init(&console_cv_lock, NULL);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);
	serv_addr.sin_addr.s_addr = inet_addr(IP);

	connect(sockfd, (struct sockaddr*) &serv_addr, sizeof serv_addr);

	printf("%s\n", "Enter a username (max 20 characters, no spaces):");
	
	while(1)
	{
		char buffer[BUFF_SIZE];
		username[0] = '\0';
		fgets(username, sizeof username, stdin);
		/* fgets also reads the \n from stdin, strip it */
		username[strlen(username) - 1] = '\0';
		register_username(sockfd);
		read(sockfd, buffer, sizeof buffer);
		if(strncmp(buffer, "fail", 4) == 0)
		{
			printf("Same name already exists! Please use another name!\n");
			continue;
		}	
		printf("*");	
		break;
	}
	pthread_create(&receiver_thread, NULL, receiver, (void*)&sockfd);
	console(sockfd);

	return 0;
}

