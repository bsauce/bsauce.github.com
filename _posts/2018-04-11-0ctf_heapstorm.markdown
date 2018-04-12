---
layout: post
title: 奇淫技巧：利用unsorted chunk到large bin的攻击方案
date: 2018-04-11 13:32:20 +0300
description: 
img: kcah.jpg # Add image post (optional)
tags: [pwn]
---
首先来看看在unsorted bin中查找可用块的过程，从unsorted bin中最后一个块找起，利用bk指针进行遍历。若unsorted bin中只有1个块（该块是the last remainder），并且该块恰好适合申请大小，则直接分割该块，remainder chunk将被放进unsorted bin；若unsorted bin中有多个块，继续遍历，若找到一个大小刚好等于申请大小的unsorted chunk，直接返回该块；否则继续遍历，在unsorted bin中找块时，先把unsorted bin中的块全放进small bin/large bin，再根据最小最适合的原则在small bin/large bin中寻找并切割块，remainder chunk将被放进unsorted bin。

实现此利用需要对unsorted chunk查找和插入large bin的代码非常熟悉，可参考对此过程相应源码的详细解读<https://dangokyo.me/2018/04/07/a-revisit-to-large-bin-in-glibc/>，也可以看我的博客<https://bsauce.github.io/2018/04/10/review_largebin>。

我们利用的就是把unsorted chunk放进large bin的这个过程。large bin中的块，是从大到小排列，同一大小的首块的fd_nextsize（指向后一个小块），bk_nextsize（指向前一个大块）才有意义。

首先以0CTF2018的一道题heapstorm2来进行原理讲解。

## 1.功能分析
首先调用mmap申请一段空间，地址已经确定为0x13370000，0x13370800用于存放数据（large_chunk）；同时调用mallopt(1,0)，即把global_fast_max改为0 ，禁用fastbin。总共能创建0-15个chunk。

  0x13370800处的数据格式如下：

    random_number1+random_number2

    random_number3+random_number3

    encrypt_chunk0_ptr+ encrypt_chunk0_size

    encrypt_chunk1_ptr+……

  其中，chunk_addr是和random_number1进行异或，chunk_size是和random_number2进行异或。

  （1）Allocate：输入size，0xc<size<=0x1000。用calloc分配空间chunk_addr（有初始化）。chunk_addr+size加密后存放于large_chunk，故1个结构占24字节。

  （2）Update：输入index、size、content，只能输入size-12字节，之后添加13个字节，有1个null字节溢出。如图

  （3）Delete：输入index，释放并清零。

  （4）View：必须random_number3^ random_number3==0x13377331，才能输入index，输出相关信息。调用write，能强制输出size大小的字节。

  保护全开。

## 2.漏洞

  update功能中，堆上的1个null字节溢出。如图所示：

![update2]({{site.baseurl}}/assets/img/update2.png)

## 3.问题

  （1）泄露地址：可以利用null字节溢出构造重叠块，问题是必须random_number3^ random_number3==0x13377331，才能泄露地址。

  （2）想用unlink，但是存放数据的0x13370800地址处都是加密存放。

  （3）想用fastbin attack，但是一开始调用了mallopt(1,0)禁用了fastbin。

## 4.利用

#### 1.构造重叠块

原理参见https://heap-exploitation.dhavalkapil.com——Shrinking Free Chunks

原理总结如下：

（1）a=malloc(0x18)；b=malloc(0x508)；c=malloc(0x18)；布置好b在偏移0x4f0处的prev_size=0x500。

（2）free(b);（0x510-unsorted bin）；a溢出把b块的size覆盖为0x500；

（3）b1=malloc(0x18)；b2/b3=malloc(0x4d8)；

（4）free(b1)；free(c)；（此时c块的prev_size没改变，prev_in_use=0没变，和b合并，总大小0x530）

（5-1）malloc(0x38)；x=malloc(0x4e8)；（此时有了重叠块x-0x4f0和b2，b2可以任意修改x）。#x就是块2，b2—块7。

（5-2）malloc(0x48);   此时unsorted bin中有了y（0x4e0）和b3重叠块，b3可以任意修改y。 #b3—块8。

#### 2.构造unsorted chunk—x和large chunk—y

  把y放进large bin，只需要把x释放申请再释放即可，这样得到了一个unsorted chunk-x和一个large chunk-y。x>y，这样一来，x和y都可控可控，就可以利用unsorted chunk插入large bin的过程来进行攻击了。

#### 3.伪造unsorted chunk和large chunk

  storage=0x13370800。

  目标地址：storage-0x20

  总共3个伪造点：

伪造点1：unsorted chunk—x的BK指针——指向目标地址。unsorted bin查找是从尾部查找，通过BK指针进行遍历，所以BK要指向目标地址。

伪造点2：large chunk—y的BK指针——指向可读可写地址（例如目标地址+8）。因为x>y，large bin是从大到小排列，所以会把x插入到y前面，y->bk->fd=x。如果恰好是目标地址+8，就会把目标地址的bk（0x18）改成x地址，这样unsorted bin遍历就又回到了x这个移除块，很巧妙，不过没必要。

伪造点3：large chunk—y的bk_nextsize指针——目标地址-0x18-5（也即目标地址的size）。x插入到y前面时会有y-bk_nextsize=x，利用它和偏移差可以把目标地址的size写为0x55或0x56，看运气了。

利用到了malloc.c中如下代码：
{% highlight c %}
```
    //1.从unsorted bin中移除块。若unsorted bin中含多个chunk,先把它从unsorted中取出来。house of orange用的是这一点。bck是移除块victim的bk(也即前一块)。
    unsorted_chunks (av)->bk = bck;   //伪造点1——目标块被插入到unsorted bin，这样下次遍历就去取用伪造块
    bck->fd = unsorted_chunks (av);   //伪造点1——目标块的fd指向unsorted bin(没用)
    
    //2.设置该移除块的fd_nextsize和bk_nextsize。fwd——被移除块将放在它前面，这里就是y，移除块victim——x。
    victim->fd_nextsize = fwd;
    victim->bk_nextsize = fwd->bk_nextsize;
    fwd->bk_nextsize = victim;                //伪造点3——large chunk的bk_nextsize指针，伪造点3——指向移除块，利用这里构造目标地址的size
    victim->bk_nextsize->fd_nextsize = victim;
    
    bck = fwd->bk;
    
    //3.设置该移除块的fd和bk。
    victim->bk = bck;         //设置好FD/BK
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;         //伪造点2——fd处指向unsorted 移除块，可以使得目标块的BK改为这个移除块，这样下次遍历就到这个移除块了。伪造点2没必要，只要指向一个可访问地址即可，反正之后就不再申请块了，除非还需要申请块。
```
{% endhighlight%}
#### 4.分配到目标地址

malloc(0x48)  。#chunk2_ptr

  当unsorted bin遍历到倒数第2个块时，实际上在判断目标地址那个块，此时目标地址处的size已经被写成了0x55/0x56，而申请的size恰好符合。所以刚好申请到目标地址这个块。

  注意：必须目标地址的size==0x56，否则以下检查会出错。

{% highlight c %}
    3436    mem = _int_malloc (av, sz);
    3437  
    3438    assert (!mem || chunk_is_mmapped (mem2chunk (mem)) ||
    3439            av == arena_for_chunk (mem2chunk (mem)));
{% endhighlight%}
可以看到目标地址处的情况：

{% highlight c %}
    pwndbg> x /30xg 0x00000000133707e0-0x10
    0x133707d0: 0x0000000000000000  0x0000000000000000
    0x133707e0: 0x2108d1a060000000  0x0000000000000056
    0x133707f0: 0x00007f0347c40b78  0x0000562108d1a060
    0x13370800: 0xd9140e94ea7ca2f1  0x13eb99db94f91fe8
    0x13370810: 0xecb34aaa36d5fb94  0xecb34aaa36d5fb94
    0x13370820: 0xd91458b5e2ad02e1  0x13eb99db94f91ff0
    0x13370830: 0xd91458b5e2ad02c1  0x13eb99db94f91fd1
    0x13370840: 0xd9140e94f94ba501  0x13eb99db94f91fa0
    0x13370850: 0xd91458b5e2ad0791  0x13eb99db94f91ff0
    0x13370860: 0xd91458b5e2ad0771  0x13eb99db94f91fa0
    0x13370870: 0xd9140e94ea7ca2f1  0x13eb99db94f91fe8
    0x13370880: 0xd91458b5e2ad0841  0x13eb99db94f91ff0
    0x13370890: 0xd91458b5e2ad02a1  0x13eb99db94f91b30
    0x133708a0: 0xd91458b5e2ad0751  0x13eb99db94f91b30
    0x133708b0: 0xd9140e94ea7ca2f1  0x13eb99db94f91fe8
    unsortedbin
    all: 0x562108d1a060 ◂— 0x7f0347c40b78
    smallbins
    empty
    largebins
    0x4c0: 0x562108d1a5c0 ◂— 0x0
    pwndbg> x /6xg 0x562108d1a060
    0x562108d1a060: 0x0000000000000000  0x00000000000004f1
    0x562108d1a070: 0x00007f0347c40b78  0x00000000133707e8
    0x562108d1a080: 0x0000562108d1a5c0  0x00000000133707c3
    pwndbg> x /6xg 0x562108d1a5c0
    0x562108d1a5c0: 0x0000000000000000  0x00000000000004e1
    0x562108d1a5d0: 0x0000000000000000  0x0000562108d1a060
    0x562108d1a5e0: 0x0000000000000000  0x0000562108d1a060
{% endhighlight%}


#### 5.泄露heap、libc  &  修改free_hook

  接下来的过程就顺理成章了。

  storage=0x13370800

  通过chunk2_ptr覆盖random_number1、random_number2、random_number3、chunk0_ptr（storage）。

  通过chunk0_ptr覆盖chunk0_ptr（storage），chunk1_ptr（指向存堆地址的地方—storage-0x20+3）。

  通过chunk1_ptr泄露heap。

  通过chunk0_ptr覆盖chunk0_ptr（storage），chunk1_ptr（指向存libc地址的地方—heap+0x10）。

  通过chunk1_ptr泄露libc。

  通过chunk0_ptr覆盖chunk0_ptr（storage），chunk1_ptr（free_hook），chunk2_ptr（storage+0x50）、storage+0x50处放置'/bin/sh\0'。

  通过chunk1_ptr修改free_hook为system。

  delete(2)。

  获得shell。

exp可参见<https://gist.github.com/Jackyxty/9de01a0bdfe5fb6d0b40fe066f059fa3>

## 5.问题再现

利用unsorted chunk到large bin的攻击方案的前提条件：

  1.地址完全随机化，我即使利用偏移差欺骗也不能找到某个地方有合适的size（如0x7f,0x56）。

  2.调用了mallopt(1,0)禁用fastbin，即使泄露了地址，也没办法用fast bin attack和0x7f来实现攻击。

  3.chunk地址进行了异或加密，没办法利用unlink实现攻击。

## 6.总结攻击方法

目标：

  1.利用unsorted chunk到large bin的攻击方案往目标地址的size区域写入0x56。

  2.利用unsorted bin的查找特性，匹配到目标地址。

方法：

  1.利用块重叠构造好1个可控的unsorted chunk和1个可控的large chunk，前者大于后者。

  2.构造好伪造点1，即unsorted chunk的bk指向目标地址，目的是申请到伪造块。

  3.构造好伪造点2，即large chunk的bk指针可访问，建议设成目标地址+8。

  4.构造好伪造点3，即large chunk的bk_nextsize指向目标地址-0x18-5，目的是布置好伪造块的size。
