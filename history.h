/* AUTHOR: Lishai Rubinstein
 * STUDENT ID: 2495 8264 */

/* history.h */
#ifndef HISTORY_H
#define HISTORY_H

#define HISTORY_MAX 5

/* Linked list node for file history queue */
typedef struct HistoryNode {
    char filename[256];
    struct HistoryNode *next;
} HistoryNode;



/*
 * history_add
 * Adds a filename to the tail of the history queue.
 * If the queue already contains HISTORY_MAX entries, the oldest (head)
 * is removed and freed before the new entry is added.
 * Parameters:
 *   filename - null-terminated filename string to record
 */
void history_add(const char *filename);

/*
 * history_display
 * Prints all filenames currently in the history queue, from oldest
 * to most recent.
 */
void history_display(void);

/*
 * history_free
 * Frees all nodes in the history queue. Must be called before program exit
 * to avoid memory leaks.
 */
void history_free(void);

#endif /* HISTORY_H */
