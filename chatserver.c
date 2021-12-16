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

#define BUFF_SIZE 256
#define USERNAME_MAX_SIZE 20

struct client_node {
	int sockfd;
	char username[USERNAME_MAX_SIZE];
	struct client_node *next;
};

struct client_node *client_list = NULL;

pthread_mutex_t client_list_lock;
pthread_mutex_t client_kick_lock;

struct client_node *add_client(int cfd) // cfd : 유저 소켓
{
	struct client_node *p = client_list;
	struct client_node *c = malloc(sizeof(struct client_node));
	c->sockfd = cfd;
	c->username[0] = '\0';
	c->next = NULL;

	pthread_mutex_lock(&client_list_lock);
	while(p && p->next)
		p = p->next;
	if(p == NULL) // 첫 번째 유저면
		client_list = c;
	else 
		p->next = c;

	pthread_mutex_unlock(&client_list_lock);
	return c;
}


struct client_node *search_client_list(char *recipient)
{
	struct client_node *p = client_list;
	if(recipient == NULL || *recipient == '\0')
		return NULL;

	pthread_mutex_lock(&client_list_lock);
	while(p != NULL) {
		if(strcmp(p->username, recipient) == 0) {
			pthread_mutex_unlock(&client_list_lock);
			return p;
		}
		p = p->next;
	}
	pthread_mutex_unlock(&client_list_lock);
	return NULL;
}

void remove_client(struct client_node *c)
{
	struct client_node *p, *prev;
	p = client_list;
	prev = NULL;

	pthread_mutex_lock(&client_list_lock);
	if(p == c) {
		client_list = p->next;
		pthread_mutex_unlock(&client_list_lock);
		return;
	}
	while(p != c && p != NULL) {
		prev = p;
		p = p->next;
	}
	if(prev && p)
		prev->next = p->next;
	pthread_mutex_unlock(&client_list_lock);
}

char *get_username(struct client_node *cnode)
{
	char *str = malloc(38);
	read(cnode->sockfd, str, 38);

	if(search_client_list(strrchr(str, ' ') + 1) != NULL)
		return "";
	return strrchr(str, ' ') + 1;
}

void *handle_client(void* c)
{
	char buffer[BUFF_SIZE] = {0};
	struct client_node *cnode, *targetnode, *tmpnode;
	char *recipient, *msg, *tmp, *formatted_msg;

	cnode = (struct client_node *)c;

	while(1)
	{
		strcpy(cnode->username, get_username(cnode));
		if(strcmp(cnode->username, "") == 0)
		{
			write(cnode->sockfd, "fail", strlen("fail"));
			continue;
		}
		write(cnode->sockfd, "success", strlen("success"));
		break;
	}
	
	printf("user: %s, socket: %d, thread:%lu\n",
		cnode->username, cnode->sockfd, (unsigned long)pthread_self());

	while(1) {
		memset(buffer, 0, sizeof buffer);
		/* read() call blocks till receipt of a msg */
		read(cnode->sockfd, buffer, sizeof buffer);

		if(strncmp(buffer, "exit", 4) == 0) {
			/* clean up when a client quits */
			remove_client(cnode);
			close(cnode->sockfd);
			free(cnode);
		}

		if(strncmp(buffer, "ls", 2) == 0) {
			memset(buffer, 0, sizeof buffer);
			tmpnode = client_list;
			while(tmpnode) {
				/* 메세지 취합 */
				strcat(buffer, tmpnode->username);
				strcat(buffer, "\n");
				tmpnode = tmpnode->next;
			}
			/* 유저 리스트 출력 */
			write(cnode->sockfd, buffer, strlen(buffer));
		}

		if(strncmp(buffer, "send ", 5) == 0) {
			/* 명령어 분해 */
			tmp = strchr(buffer, ' ');
			if(tmp == NULL)
				continue;
			recipient = tmp + 1;

			tmp = strchr(recipient, ' ');
			if(tmp == NULL)
				continue;
			*tmp = '\0';
			msg = tmp + 1;

			/* 유저 검색 */
			targetnode = search_client_list(recipient);

			/* 찾는 유저가 없을 시 */
			if(targetnode == NULL)
				continue;

			formatted_msg = malloc(BUFF_SIZE);
			/* 오버플로우 방지 */
			if(BUFF_SIZE < strlen(cnode->username) + strlen(msg) + 2)
				continue;
			/* 보낼 메시지 형태 제작 */
			sprintf(formatted_msg, "\n%s: %s", cnode->username, msg);
			printf("%s sent msg to %s\n", cnode->username, targetnode->username);
			/* 전송 */
			write(targetnode->sockfd, formatted_msg, strlen(formatted_msg) + 1);
			free(formatted_msg);
		}
		
		if(strncmp(buffer, "all ", 4) == 0) {
			/* 명령어 분해 */
			tmp = strchr(buffer, ' ');
			if(tmp == NULL)
				continue;
			*tmp = '\0';
			msg = tmp + 1;
						
			/* 오버플로우 방지 */
			if(BUFF_SIZE < strlen(cnode->username) + strlen(msg) + 2)
				continue;
			/* 보낼 메시지 형태 제작 */
			formatted_msg = malloc(BUFF_SIZE);
			sprintf(formatted_msg, "\n%s: %s", cnode->username, msg);
			tmpnode = client_list;
			pthread_mutex_lock(&client_list_lock);
			while(tmpnode) {
				if(tmpnode->username != cnode->username)		
					write(tmpnode->sockfd, formatted_msg, strlen(formatted_msg) + 1);				
				tmpnode = tmpnode->next;
			}
			printf("%s sent msg to all\n", cnode->username);			
			free(formatted_msg);
			pthread_mutex_unlock(&client_list_lock);
		}
	}

	pthread_mutex_destroy(&client_list_lock);
	close(cnode->sockfd);
	return NULL;
}

void error(void)
{
	fprintf(stderr, "%s\n", "bad command\n"
		"Type 'help' to see the lists of commands.");
}

void *console(void* c)
{	
	while(1)
	{
		char buffer[BUFF_SIZE] = {0};
		struct client_node *cnode, *targetnode, *tmpnode;
		char *recipient, *msg, *tmp, *formatted_msg, *formatted_msg2;
		
		fgets(buffer, sizeof buffer, stdin);
		
		if(buffer == NULL)
			continue;
			
		if(strncmp(buffer, "help", 2) == 0) {
			printf("%s%s%s%s\n\n",
			"\nls : show list of members",
			"\nsend [username] [message] : send message to specific user",
			"\nall [message] : send message to all",
			"\nkick [username] [reason] : kick the user and tell everyone about it");
			continue;
		}
		
		if(strncmp(buffer, "ls", 2) == 0) {
			memset(buffer, 0, sizeof buffer);
			tmpnode = client_list;
			while(tmpnode) {
				/* 메세지 취합 */
				strcat(buffer, tmpnode->username);
				strcat(buffer, "\n");
				tmpnode = tmpnode->next;
			}
			/* 유저 리스트 출력 */
			printf("%s",buffer);
			continue;
		}
		
		if(strncmp(buffer, "send ", 5) == 0) {
			/* 명령어 분해 */
			tmp = strchr(buffer, ' ');
			if(tmp == NULL)
				continue;
			recipient = tmp + 1;

			tmp = strchr(recipient, ' ');
			if(tmp == NULL)
				continue;
			*tmp = '\0';
			msg = tmp + 1;

			/* 유저 찾기 */
			targetnode = search_client_list(recipient);

			/* 찾는 유저가 없을 시 */
			if(targetnode == NULL)
				continue;

			formatted_msg = malloc(BUFF_SIZE);
			/* 오버플로우 방지 */
			if(BUFF_SIZE < strlen("\n[Administrator(personal)] >> ") + strlen(msg))
				continue;
			/* 보낼 메시지 형태 제작 */
			sprintf(formatted_msg, "\n[Administrator(personal)] >> %s", msg);
			/* 전송 */
			write(targetnode->sockfd, formatted_msg, strlen(formatted_msg) + 1);
			free(formatted_msg);
			continue;
		}
		
		if(strncmp(buffer, "all ", 4) == 0)				
		{
			tmp = strchr(buffer, ' ');
			if(tmp == NULL)
				continue;
			msg = tmp + 1;
			
			if(BUFF_SIZE < strlen("\n[Administrator(public)] >> ") + strlen(msg))
				continue;

			formatted_msg = malloc(BUFF_SIZE);
			sprintf(formatted_msg, "\n[Administrator(public)] >> %s", msg);
			tmpnode = client_list;
			pthread_mutex_lock(&client_list_lock);
			while(tmpnode) 
			{		
				write(tmpnode->sockfd, formatted_msg, strlen(formatted_msg) + 1);				
				tmpnode = tmpnode->next;
			}		
			free(formatted_msg);
			pthread_mutex_unlock(&client_list_lock);
			continue;
		}
		
		if(strncmp(buffer, "kick ", 5) == 0)
		{
			tmp = strchr(buffer, ' ');
			if(tmp == NULL)
				continue;
			recipient = tmp + 1; // 킥 당하는 사람

			tmp = strchr(recipient, ' ');
			if(tmp == NULL)
				continue;
			*tmp = '\0';
			msg = tmp + 1; // 킥 당하는 사유

			/* 유저 존재 확인 */
			targetnode = search_client_list(recipient);
			if(targetnode == NULL)
				continue;				
			/* 문자열 길이 검사 */
			if(BUFF_SIZE < strlen(targetnode->username) + strlen(msg) + 2)
				continue;

			formatted_msg = malloc(BUFF_SIZE);
			formatted_msg2 = malloc(BUFF_SIZE);
			sprintf(formatted_msg, "\n%s is kicked from server.\nReason: %s", targetnode->username, msg); // 모두에게 갈 메세지
			sprintf(formatted_msg2, "\nYou are kicked from server. Press Ctrl+C to end process.\nReason: %s", msg); // 킥 당한 유저에게 갈 메세지
			
			tmpnode = client_list;
			pthread_mutex_lock(&client_kick_lock);
			while(tmpnode) 
			{	
				if(targetnode == tmpnode)
					write(tmpnode->sockfd, formatted_msg2, strlen(formatted_msg2) + 1);
				else
					write(tmpnode->sockfd, formatted_msg, strlen(formatted_msg) + 1);				
				tmpnode = tmpnode->next;
			}		
			free(formatted_msg);
			free(formatted_msg2);
			remove_client(targetnode);
			printf("%s kicked successfully.\n",targetnode->username);
			close(targetnode->sockfd);
			free(targetnode);
			pthread_mutex_unlock(&client_kick_lock);
			continue;
		}
		error();
	}
}

int main(int argc, char * argv[])
{
	if(argc != 2)
	{
		printf("Usage ./filename [PORT] \n");
		exit(0);
	}
	in_port_t PORT = atoi(argv[1]);
	int sockfd, client_sockfd;

	struct sockaddr_in serv_addr, client_addr;
	unsigned int supplied_len;
	unsigned int *ip_suppliedlen_op_storedlen;


	pthread_t thread;
	pthread_t notice_thread;

	pthread_mutex_init(&client_list_lock, NULL);
	pthread_mutex_init(&client_kick_lock, NULL);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	bind(sockfd, (struct sockaddr*) &serv_addr, sizeof serv_addr);

	listen(sockfd, 5);

	supplied_len = sizeof(client_addr);
	ip_suppliedlen_op_storedlen = &supplied_len;

	printf("%s\n%s\n", 
		"Welcome to chat server console. Please enter commands",
		"Type 'help' to see the lists of commands.");
	
	pthread_create(&notice_thread, NULL, console, NULL);
	
	while(1) {
		struct client_node *cnode;
		client_sockfd = accept(sockfd, (struct sockaddr*) &client_addr,
							ip_suppliedlen_op_storedlen);
		cnode = add_client(client_sockfd);
		pthread_create(&thread, NULL, handle_client, (void*)cnode);
	}
	return 0;
}

