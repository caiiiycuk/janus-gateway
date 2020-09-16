#ifndef JSDOS_DATA_PIPE_H_
#define JSDOS_DATA_PIPE_H_

#define CHANNEL_SUPERVISOR '#'
#define CHANNEL_PIPE '$'

void jsdos_data_pipe_init(void);
void jsdos_data_pipe_write(char channel, void* buffer, int len);
void jsdos_data_pipe_destroy(void);
#endif
