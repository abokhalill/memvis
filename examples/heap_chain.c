#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct node {
    int value;
    int flags;
    struct node *next;
    struct node *prev;
} node_t;

node_t *g_head;
node_t *g_tail;

int main(void) {
    /* build a linked list of 8 nodes on the heap */
    node_t *prev = NULL;
    for (int i = 0; i < 8; i++) {
        node_t *n = (node_t *)malloc(sizeof(node_t));
        memset(n, 0, sizeof(*n));
        n->value = i * 10;
        n->flags = i;
        n->next = NULL;
        n->prev = prev;
        if (prev) prev->next = n;
        if (i == 0) g_head = n;
        prev = n;
    }
    g_tail = prev;

    /* mutate the chain */
    for (int round = 0; round < 50; round++) {
        node_t *cur = g_head;
        while (cur) {
            cur->value += 1;
            cur = cur->next;
        }
    }

    printf("heap_chain: head=%p tail=%p head->value=%d\n",
           (void*)g_head, (void*)g_tail, g_head->value);

    /* partial cleanup: free first 4 nodes, keep last 4 alive */
    node_t *c = g_head;
    for (int i = 0; i < 4 && c; i++) {
        node_t *next = c->next;
        free(c);
        c = next;
    }
    /* update g_head to point at the surviving node */
    g_head = c;
    if (c) c->prev = NULL;

    printf("heap_chain: after partial free, head=%p tail=%p\n",
           (void*)g_head, (void*)g_tail);
    return 0;
}
