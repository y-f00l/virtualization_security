# CodeQL learning

- 在github security lab上发现了一篇很有意思的文章，讲怎样用CodeQL去发现漏洞的，以rsyslog为例，宏观的讲解了CodeQL的使用，作者用这个发现了rsyslog的两个内存破坏漏洞

## 万物之始

- 既然是为了影响当前程序，一定是要找到我们可用的输入点，我们只有能输入数据，那么才能进行下一步，来对程序进行破坏，目标很明显了，就是找诸如read,recv等这种输入函数，虽然不一定全部是可控的，但是顺着这些输入函数还是可以极有可能找到我们可控的输入点的，所以用CodeQL做如下查询

  ```java
  import cpp
  
  class ReadFunctionCall() extends FunctionCall {  
  //定义了ReadFunctionCall这个类，继承Function类
  	ReadFunctionCall() {
  			this.getTarget.getName() = "pread" or
  			this.getTarget.getName() = "read" or
  			this.getTarget.getName() = "readv" or
  			this.getTarget.getName() = "recvfrom" or
  			this.getTarget.getName() = "recv" or 
  			this.getTarget.getName() = "recvmsg"
  			//this是这个类本身，调用Function中的getTarget方法，然后再调用Target中的getName方法，和我们想找的			//输入函数名进行比较，从而筛选出来
  	}
  }
  
  from ReadFunctionCall call
  select call.getFile(), call.getEnclosingFucntion(), call
  //筛选那些输入函数，通过getFile获取他们在哪个文件，然后通过getEnclosingFunction获取哪个函数调用他们了
  ```

- 这样就能查询出所有调用了这些函数的文件名，调用这些输入函数的函数，还有具体调用了哪个输入函数

- | **Filename**                                   | **Function name**       | Read call |
  | ---------------------------------------------- | ----------------------- | --------- |
  | /rsyslog/action.c                              | checkExternalStateFile  | read      |
  | /rsyslog/contrib/imbatchreport/imbatchreport.c | readAndSendFile         | read      |
  | /rsyslog/plugins/imfile/imfile.c               | getFileID               | read      |
  | /rsyslog/plugins/imklog/bsd.c                  | klogWillRunPostPrivDrop | read      |
  | /rsyslog/plugins/imudp/imudp.c                 | processSocket           | recvmsg   |
  | /rsyslog/plugins/imuxsock/imuxsock.c           | readSocket              | recvmsg   |
  | /rsyslog/contrib/improg/improg.c               | readChild               | read      |
  |                                                |                         |           |
  |                                                |                         |           |

  看上面的一部分查询结果，可以发现rsyslog是为了从不同的输入流读文件实现的，不同的输入源有不同的module实现，如下

  - improg：read from a program's output.
  - imfile：read from regular files.
  - imklog：read from klog.
  - imudp：read from UDP sockets.
  - imuxsock：read from UNIX sockets.

- 从不同的输入流中选择了 read from UDP sockets这个输入流，因为从套接字中读数据，我感觉这里的输入是很有可能可控的，所以选择了imudp.c中的processSocket函数，然后进这个函数看一下。

  ```c
  static rsRetVal
  processSocket(struct wrkrInfo_s *pWrkr, struct lstn_s *lstn, struct sockaddr_storage *frominetPrev, int *pbIsPermitted)
  {
      ssize_t lenRcvBuf;
      multi_submit_t multiSub;
      smsg_t *pMsgs[CONF_NUM_MULTISUB];
      struct msghdr mh;
      struct iovec iov[1];
  
      multiSub.ppMsgs = pMsgs;
      multiSub.maxElem = CONF_NUM_MULTISUB;
      multiSub.nElem = 0;
  
      while(1) {
          memset(iov, 0, sizeof(iov));
          iov[0].iov_base = pWrkr->pRcvBuf;
          iov[0].iov_len = iMaxLine;
  
          memset(&mh, 0, sizeof(mh));
          mh.msg_name = &frominet;
          mh.msg_namelen = sizeof(struct sockaddr_storage);
          mh.msg_iov = iov;
          mh.msg_iovlen = 1;
  
          lenRcvBuf = recvmsg(lstn->sock, &mh, 0);
  
          if(lenRcvBuf < 0) {
              if(errno != EINTR && errno != EAGAIN) {
                  rs_strerror_r(errno, errStr, sizeof(errStr));
                  DBGPRINTF("INET socket error: %d = %s.\n", errno, errStr);
                  LogError(errno, NO_ERRCODE, "imudp: error receiving on socket: %s", errStr);
              }
  
              ABORT_FINALIZE(RS_RET_ERR);
          }
  
          processPacket(lstn, frominetPrev, pbIsPermitted, pWrkr->pRcvBuf, lenRcvBuf, &stTime, ttGenTime, &frominet, mh.msg_namelen, &multiSub);
      }
  
  finalize_it:
      multiSubmitFlush(&multiSub);
      RETiRet;
  }
  ```

- 审察这个函数，就是简单的设置了一下mh(我这里猜是message header)

- 然后把message读取到缓冲区也就是pWrkr->p_RcvBuf，然后传给processPacket，跟进processPacket函数

  ```C
  static rsRetVal
  processPacket(struct lstn_s *lstn, struct sockaddr_storage *frominetPrev, int *pbIsPermitted, uchar *rcvBuf, ssize_t lenRcvBuf, struct syslogTime *stTime, time_t ttGenTime, struct sockaddr_storage *frominet, socklen_t socklen, multi_submit_t *multiSub)
  {
      smsg_t *pMsg = NULL;
      
      if(bDoACLCheck) {
          // REMOVED: Access control lists checks ...
      } else {
          *pbIsPermitted = 1; /* no check -> everything permitted */
      }
  
      if(*pbIsPermitted != 0)  {
          CHKiRet(msgConstructWithTime(&pMsg, stTime, ttGenTime));
          
          MsgSetRawMsg(pMsg, (char*)rcvBuf, lenRcvBuf);
          pMsg->msgFlags  = NEEDS_PARSING | PARSE_HOSTNAME | NEEDS_DNSRESOL;
          
          CHKiRet(ratelimitAddMsg(lstn->ratelimiter, multiSub, pMsg));
          STATSCOUNTER_INC(lstn->ctrSubmit, lstn->mutCtrSubmit);
      }
  
  finalize_it:
      if(iRet != RS_RET_OK) {
          if(pMsg != NULL && iRet != RS_RET_DISCARDMSG) {
              msgDestruct(&pMsg);
          }
      }
  
      RETiRet;
  }
  ```

- 这个函数更简单，主要任务就是access control check，如果everything permitted了，那么就调用msgConstrucWithTime来对一个smsg_t的对象进行构造，然后传给MsgSetRawMsg。

- 对于第一个函数应该就是简单的初始化，不需要看，直接去看后一个，因为后一个应该是对smsg_t对象进行内容设置，代码如下

  ```c
  void MsgSetRawMsg(smsg_t *const pThis, const char *const pszRawMsg, const size_t lenMsg)
  {
      if (pThis->pszRawMsg != pThis->szRawMsg)
          free(pThis->pszRawMsg);
  
      deltaSize = (int)lenMsg - pThis->iLenRawMsg; /* value < 0 in truncation case! */
      pThis->iLenRawMsg = lenMsg;
      if (pThis->iLenRawMsg < CONF_RAWMSG_BUFSIZE)
      {
          /* small enough: use fixed buffer (faster!) */
          pThis->pszRawMsg = pThis->szRawMsg;
      }
      else if ((pThis->pszRawMsg = (uchar *)malloc(pThis->iLenRawMsg + 1)) == NULL)
      {
          /* truncate message, better than completely loosing it... */
          pThis->pszRawMsg = pThis->szRawMsg;
          pThis->iLenRawMsg = CONF_RAWMSG_BUFSIZE - 1;
      }
  
      memcpy(pThis->pszRawMsg, pszRawMsg, pThis->iLenRawMsg);
      pThis->pszRawMsg[pThis->iLenRawMsg] = '\0'; /* this also works with truncation! */
      
      /* correct other information */
      if (pThis->iLenRawMsg > pThis->offMSG)
          pThis->iLenMSG += deltaSize;
      else
          pThis->iLenMSG
  }
  ```

- 在这里我们看到了，对smsg_t对象的iLen进行判断，如果过小就不申请新的空间，如果比较大的话，那么就申请一个buffer，然后把pszRawMsg的内容copy进去，这个pszRawMsg就是我们想找的可控输入点，流程如下

- processSocket->processPacket->MsgSetRawMsg

- 既然跟着这个从UDP中读数据的调用链找到了用户输入点，我们就只要追踪这个变量就好了，写出如下查询语句

  ```java
  import cpp
  
  class RawMessageFieldAccess extends FieldAccess {
    //定义了RawMessageFieldAccess这个类，继承FieldAccess，这个类从名字猜测就是查询哪里引用了变量
  		RawMessageFieldAccess() {
  				this.getTarget.getName() = "pszRawMsg"
          //刚刚我们找到的用户输入点，通过getTarget拿到Target再调用Target的getName方法，找到引用用户输入				//点的位置
  		}
  }
  
  class RawMsgAccessFunction extends Function {
  		RawMsgAccessFunction() {
  				any(RawMessageFieldAccess access).getEnclosingFunction() == this
          //寻找包含了用户输入点的函数
  		}
  }
  
  from RawMsgAccessFunction access
  select access.getFile(), access
  //筛选出那些带有用户输入点的函数，然后他们所在的文件
  ```

- 根据这个筛选出来的结果，发现了一些有意思的函数，他们返回了指向用户输入的指针，分别是`getMSG` ` getRawMsg`

- 所以我们也可以找那些调用了getMsg和getRawMsg的函数，这样我们输入的数据也可能在那里对程序有影响

- 更改一下筛选语句

  ```java
  import cpp
  
  class RawMessageFieldAccess extends FieldAccess {
    //定义了RawMessageFieldAccess这个类，继承FieldAccess，这个类从名字猜测就是查询哪里引用了变量
  		RawMessageFieldAccess() {
  				this.getTarget.getName() = "pszRawMsg"
          //刚刚我们找到的用户输入点，通过getTarget拿到Target再调用Target的getName方法，找到引用用户输入				//点的位置
  		}
  }
  
  class RawMsgAccessFunction extends Function {
  		RawMsgAccessFunction() {
  				any(RawMessageFieldAccess access).getEnclosingFunction() == this
          or
          exists( Function call |
          	call.getTarget.getEnclosingFunction() = this and (
          		call.getTarget.getNmae = "getMsg" or
            	call.getTarget.getName = "getRawMsg"
          	)
          )
          //寻找包含了用户输入点的函数,还有调用`返回指向用户输入的指针的函数`的函数
  		}
  }
  from RawMsgAccessFunction access
  select access.getFile(), access
  //筛选出那些带有用户输入点的函数，然后他们所在的文件
  ```

- 匹配到的结果

| **Filename**                                             | **Function**      |
| -------------------------------------------------------- | ----------------- |
| /rsyslog/runtime/parser.c                                | ParseMsg          |
| /rsyslog/contrib/pmaixforwardedfrom/pmaixforwardedfrom.c | parse             |
| /rsyslog/runtime/parser.c                                | uncompressMessage |
| /rsyslog/contrib/pmcisconames/pmcisconames.c             | parse             |
| /rsyslog/plugins/pmlastmsg/pmlastmsg.c                   | parse             |
| /rsyslog/tools/pmrfc3164.c                               | parse2            |
| /rsyslog/tools/pmrfc5424.c                               | parse             |

- (只选了一部分结果出来)我们在这些函数里看，发现有和runtime相关的函数，分别是ParseMsg和uncompressMessage

- 查看一下uncompressMessage函数

  ```c
  static rsRetVal uncompressMessage(smsg_t *pMsg)
  {
      pszMsg = pMsg->pszRawMsg;
      lenMsg = pMsg->iLenRawMsg;
  
      if(lenMsg > 0 && *pszMsg == 'z') {
          int ret;
          iLenDefBuf = glbl.GetMaxLine();
          CHKmalloc(deflateBuf = malloc(iLenDefBuf + 1));
          ret = uncompress((uchar *) deflateBuf, &iLenDefBuf, (uchar *) pszMsg+1, lenMsg-1);
  
          if(ret != Z_OK) {
              FINALIZE;
          }
          MsgSetRawMsg(pMsg, (char*)deflateBuf, iLenDefBuf);
      }
      
  finalize_it:
      if(deflateBuf != NULL)
          free(deflateBuf);
  
      RETiRet;
  }
  ```

- 发现调用了uncompress这个属于zlib库的函数，zlib有历史漏洞爆出，如果有相关漏洞的exp可以对这里进行攻击，剩下的就没什么了。来看Parse函数

- ParseMsg函数就是一个针对parse和parse2函数的分发器，然后这样我们的数据是流向parse和parse2函数的，写出如下查询语句

  ```java
  import cpp
  
  class ParseFunction extends Function {
  		ParseFunction() {
  			this.getName() = "parse" or
  			this.getName() = "parse2"
  		}
  }
  
  from ParseFunction parse
  select parse.getFile(), parse
  ```

- 然后剩下的就是对筛选出来的各个文件进行审计，来找漏洞

