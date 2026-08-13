/* AUTHOR: Lishai Rubinstein
 * STUDENT ID: 2495 8264 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "history.h"
 
/* Queue state: head is oldest, tail is newest */
static HistoryNode *head = NULL;
static HistoryNode *tail = NULL;
static int count = 0;
 
void history_add(const char *filename) {
    if (!filename || strlen(filename) == 0) return;

    /* If queue is full, removes head, if head is NULL, 
    tail is set to NULL to avoid an invalid pointer */
    if (count == HISTORY_MAX) {
        HistoryNode *old = head;
        head = head->next;
        if (head == NULL) tail = NULL;
        free(old);
        count--;
    }
 
    /* Allocates memeory for a new node, copies file name, sets 
    next to NULL as it's the last node in the queue */
    HistoryNode *node = malloc(sizeof(HistoryNode));
    if (!node) {
        printf("Error: could not allocate history node.\n");
        return;
    }
    strncpy(node->filename, filename, 255);
    node->filename[255] = '\0';
    node->next = NULL;
 
    if (tail == NULL) {
        head = tail = node;
    } else {
        tail->next = node;
        tail = node;
    }
    count++;
}
 
/*Prints the linked list from head to tail (numbered), if
queue is empty it prints "No recent files." and returns*/
void history_display(void) {
    if (head == NULL) {
        printf("No recent files.\n");
        return;
    }
    printf("\n=== Recent Files ===\n");
    HistoryNode *cur = head;
    int i = 1;
    while (cur != NULL) {
        printf("%d. %s\n", i++, cur->filename);
        cur = cur->next;
    }
}

/*saves the next pointer before freeing nodes, after the loop, it
 resets all three state variables, creating a clean empty state*/
void history_free(void) {
    HistoryNode *cur = head;
    while (cur != NULL) {
        HistoryNode *next = cur->next;
        free(cur);
        cur = next;
    }
    head = tail = NULL;
    count = 0;
}
 
