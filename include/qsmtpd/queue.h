/** @file queue.h
 * @brief function definitions for communication with qmail-queue
 */

#ifndef QSMTPD_QUEUE_H
#define QSMTPD_QUEUE_H

extern int queuefd_data; /**< fd to send message data to qmail-queue */
extern int queuefd_hdr;  /**< fd to send header data to qmail-queue */

extern void queue_reset(void);
extern int queue_init(void);
extern int queue_envelope(const unsigned long msgsize, const int chunked);
extern int queue_result(void);

#endif /* QSMTPD_QUEUE_H */
