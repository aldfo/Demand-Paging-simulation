#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <limits.h>

#define PAGESIZE         (32)
#define PAS_FRAME        (256)
#define PAS_SIZE         (PAGESIZE * PAS_FRAME)            // 32 * 256 = 8192 Byte
#define VAS_PAGES        (64)
#define VAS_SIZE         (PAGESIZE * VAS_PAGES)            // 32 * 64 = 2048 Byte
#define PTE_SIZE         (4)                               // sizeof(pte)
#define PAGETABLE_FRAMES (VAS_PAGES * PTE_SIZE / PAGESIZE) // 64 * 4 / 32 = 8 consecutive frames
#define PAGE_INVALID     (0)
#define PAGE_VALID       (1)
#define MAX_REFERENCES   (256)

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next) {
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head) {
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head) {
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head * prev, struct list_head * next) {
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry) {
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

static inline void list_del_init(struct list_head *entry) {
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
}

static inline void list_move(struct list_head *list, struct list_head *head) {
        __list_del(list->prev, list->next);
        list_add(list, head);
}

static inline void list_move_tail(struct list_head *list,
				  struct list_head *head) {
        __list_del(list->prev, list->next);
        list_add_tail(list, head);
}

static inline int list_empty(const struct list_head *head) {
	return head->next == head;
}

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_for_each(pos, head) \
  for (pos = (head)->next; pos != (head);	\
       pos = pos->next)

#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; prefetch(pos->prev), pos != (head); \
        	pos = pos->prev)

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_entry((head)->prev, typeof(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = list_entry(pos->member.prev, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_entry((head)->prev, typeof(*pos), member),	\
		n = list_entry(pos->member.prev, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.prev, typeof(*n), member))

#if 0    //DEBUG
#define debug(fmt, args...) fprintf(stderr, fmt, ##args)
#else
#define debug(fmt, args...)
#endif


typedef struct{
    unsigned char frame;
    unsigned char vflag;
    unsigned char ref;
    unsigned char pad;
} pte;

typedef struct{
    int pid;
    int ref_len;
    unsigned char *ref;
    int pagefault_cnt;
    int reference_cnt;
    struct list_head list;
} process_raw;

typedef struct{
    unsigned char b[PAGESIZE];
} frame;

process_raw *cur, *next;
LIST_HEAD(job);
frame * pas;
int free_frame;             // free상태 frame index
int proc_num = 0;           // process의 개수

void Load_proc(){
    process_raw data;
    while(fread(&data, sizeof(int) * 2, 1, stdin) != 0){
        cur = malloc(sizeof(process_raw));
        cur->pid = data.pid;
        cur->ref_len = data.ref_len;
        cur->pagefault_cnt = 0;
        cur->reference_cnt = 0;
        cur->ref = malloc(sizeof(unsigned char) * cur->ref_len);
        for(int i=0;i<cur->ref_len;i++){
            fread(&cur->ref[i], sizeof(unsigned char), 1, stdin);
        }
        INIT_LIST_HEAD(&cur->list);
        list_add_tail(&cur->list, &job);
        proc_num++;
    }
}

void init_pas(){
    pas = (frame*)malloc(PAS_SIZE);
    free_frame = proc_num * 8;
    for(int i=0;i<free_frame;i++){
        pte *cur_pte = (pte*)&pas[i];
        for(int j=0;j<8;j++){
            cur_pte[j].vflag = PAGE_INVALID;
            cur_pte[j].ref = 0;
        }
    }
}

void simulator(){
    int start_frame = proc_num * 8;     // page가 할당 된 pas에서 처음 접근 가능한 index
    pte * cur_pte;
    int ref_cnt = 0;
    while(1){
        int isbreak = 1;
        list_for_each_entry(cur, &job, list){ 
            // 모두 수행했을 때
            if(cur->ref_len <= ref_cnt){
                continue;
            }
            else isbreak = 0;
            cur_pte = (pte*)&pas[cur->pid * 8 + cur->ref[ref_cnt] / 8];
            // page fault
            if(cur_pte[cur->ref[ref_cnt] % 8].vflag == PAGE_INVALID){
                // out of range
                if(start_frame >= MAX_REFERENCES){
                    printf("Out of memory!!\n");
                    isbreak = 1;
                    break;
                }
                cur_pte[cur->ref[ref_cnt] % 8].vflag = PAGE_VALID;
                cur_pte[cur->ref[ref_cnt] % 8].ref = 1;
                cur_pte[cur->ref[ref_cnt] % 8].frame = start_frame;
    
                start_frame++;
                cur->pagefault_cnt++;
                cur->reference_cnt++;
            }
            // not page fault
            else{
                cur_pte[cur->ref[ref_cnt] % 8].ref++;
                cur->reference_cnt++;
            }
        }
        if(isbreak) break;
        ref_cnt++;  
    }
}

void result_print(){
    int allocated = 0;
    int pagefault = 0;
    int reference = 0;

    list_for_each_entry(cur, &job, list){
        allocated += (cur->pagefault_cnt + 8);
        pagefault += cur->pagefault_cnt;
        reference += cur->reference_cnt;
        printf("** Process %03d: Allocated Frames=%03d PageFaults/References=%03d/%03d\n",
			   cur->pid, cur->pagefault_cnt + 8, cur->pagefault_cnt, cur->reference_cnt);
        pte* cur_pte = (pte*)&pas[cur->pid * 8];
        for(int i=0;i<64;i++){
            if(cur_pte[i].vflag == PAGE_VALID){
                printf("%03d -> %03d REF=%03d\n",i, cur_pte[i].frame, cur_pte[i].ref);
            }
        }
    }

    printf("Total: Allocated Frames=%03d Page Faults/References=%03d/%03d\n", 
		   allocated, pagefault, reference);
}

void mem_free(){
    list_for_each_entry_safe(cur, next, &job, list){
		list_del(&cur->list);    // job_q에서 연결 해제
        free(cur->ref);          // ref 할당 해제
		free(cur);               // process 할당 해제
	}
    free(pas); 					 // PAS frame 할당 해 
}
int main(){
    Load_proc();
    init_pas();제 
    simulator();
    result_print();
    mem_free();
    return 0;
}




