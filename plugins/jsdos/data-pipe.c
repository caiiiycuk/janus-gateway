#include "data-pipe.h"
#include "../../debug.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define SUPERVISOR_CHANNEL_PIPE "/tmp/p-supervisor"
#define PIPE_CHANNEL_PIPE "/tmp/p-pipe"
#define BUFFER_SIZE 32 * 1024

struct PipeChannel {
    int fd;
    int used;
    char buffer[BUFFER_SIZE];
};

_Atomic int live = 0;

pthread_t thread = 0;
pthread_cond_t cv;
pthread_mutex_t mp;

struct PipeChannel supervisorChannel = {};
struct PipeChannel pipeChannel = {};

void *jsdos_data_loop(void *arg);

void jsdos_data_pipe_init(void) {
    if (thread) {
        JANUS_LOG(LOG_ERR, "jsdos_data_pipe already initialized\n");
        abort();
    }

    pthread_create(&thread, 0, jsdos_data_loop, 0);
    if (pthread_cond_init(&cv, NULL) != 0) {
        JANUS_LOG(LOG_ERR, "jsdos_data_pipe can't create conditional variable\n");
        abort();
    }

    if (pthread_mutex_init(&mp, NULL) != 0) {
        JANUS_LOG(LOG_ERR, "jsdos_data_pipe can't create mutex\n");
        abort();
    }
}

void jsdos_data_pipe_write(char channelId, void* data, int len) {
    if (len == 0) {
        return;
    }

    struct PipeChannel *channel = 0;
    switch (channelId) {
        case CHANNEL_SUPERVISOR:
            channel = &supervisorChannel;
            break;
        case CHANNEL_PIPE:
            channel = &pipeChannel;
            break;
        default:
            JANUS_LOG(LOG_ERR, "Can't detect data channel for %c\n", channelId);
            return;
    }

    pthread_mutex_lock(&mp);
    if (channel->used + len >= BUFFER_SIZE - 1) {
        JANUS_LOG(LOG_ERR, "Data buffer overflow on channel %c\n", channelId);
        pthread_mutex_unlock(&mp);
        return;
    }
    memcpy(channel->buffer + channel->used, data, len);
    channel->buffer[channel->used + len] = '\n';
    channel->used += len + 1;
    pthread_cond_signal(&cv);
    pthread_mutex_unlock(&mp);
}

void *jsdos_data_loop(void *arg) {
    struct PipeChannel* channel;
    int copied, toWrite, written;
    char* copy = (char *) malloc(BUFFER_SIZE + 1);
    live = 1;

    mkfifo(SUPERVISOR_CHANNEL_PIPE, 0666);
    mkfifo(PIPE_CHANNEL_PIPE, 0666);

    if ((supervisorChannel.fd = open(SUPERVISOR_CHANNEL_PIPE, O_WRONLY)) == -1) {
        JANUS_LOG(LOG_ERR, "Can't open channel pipe %s\n", SUPERVISOR_CHANNEL_PIPE);
        abort();
    }

    if ((pipeChannel.fd = open(PIPE_CHANNEL_PIPE, O_WRONLY)) == -1) {
        JANUS_LOG(LOG_ERR, "Can't open channel pipe %s\n", PIPE_CHANNEL_PIPE);
        abort();
    }

    while (live) {
        pthread_mutex_lock(&mp);
        while (supervisorChannel.used == 0 && pipeChannel.used == 0 && live) {
            pthread_cond_wait(&cv, &mp);
        }

        channel = pipeChannel.used > 0 ? &pipeChannel : &supervisorChannel;
        copied = channel->used;
        memcpy(copy, channel->buffer, copied);
        channel->used = 0;
        pthread_mutex_unlock(&mp);

        toWrite = copied;
        while (toWrite > 0 && live) {
            written = write(channel->fd, copy + (copied - toWrite), toWrite);

            if (written == -1) {
                break;
            }

            toWrite -= written;
        }
    }

    free(copy);

    close(supervisorChannel.fd);
    close(pipeChannel.fd);
    return 0;
}

void jsdos_data_pipe_destroy(void) {
    live = 0;
    pthread_join(thread, NULL);
    pthread_mutex_destroy(&mp);
    pthread_cond_destroy(&cv);
    thread = 0;
}
