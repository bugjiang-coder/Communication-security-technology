
''''' 
socket 给百度发送http请求 
 
连接成功后，发送http的get请求，所搜索功能 
 
'''  
import socket  
import sys  
import time  
import ssl
if __name__=='__main__':  
    #创建套接字  
    try :  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    except socket.eorror as e:  
        print ('socket false:%s'%e  )
    print ('socket ...' ) 
     
    #连接百度ip  
    try :  
        sock.connect(('www.baidu.com',80))  
    except socket.error as e:  
        print ('connect false %s'%e)  
        sock.close()  
    print ('connect ...'  )
     
    #发送百度首页面请求并且保持连接  
    try :  
        print ('send start...'  )
        str='GET / HTTP/1.1\r\nHost:www.baidu.com\r\nConnection:keep-alive\r\n\r\n'  
        sock.send(str.encode())  
    except socket.eorror as e:  
        print ('send false' ) 
        sock.close()  
     
    data=''  
    data = sock.recv(1024)  
    while (1):       
        '''''如何判断数据接收完毕，在发送http 最前端, 
                        包含发送数据文件大小属性Content-Length， 
                        用字符匹配方式取得文件大小, 
                        同过大小判断是否接收完毕。 
        '''  

        print (data)  
        beg = data.find('Content-Length:',len(data))  
        end = data.find('Content-Type:',len(data))  
        print (beg)  
        print (end)  
        if(beg == end):  
            print ('connecting closed'  )
            break  
        num = int(data[beg+16:end-2])  
        print(num)  
        nums =   ''
        while (1):  
            data=sock.recv(1024)  
            print (data ) 
            nums +=len(data)  
            if(nums >= num):  
                break  
        word = input('please input your word----->')  
        str='''''GET /s?wd=''' + word + ''''' HTTP/1.1 
Host:www.baidu.com 
Connection: Keep-Alive 
 
'''  
        print (str)  
        sock.send(str)  
        data = ''  
        data = sock.recv(1024)     
    sock.close()  
    print (data)  