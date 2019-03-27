#include <linux/kernel.h>
#include <linux/module.h>



/*
 * HTTP method with space separator at tail
 */
#define METHOD_W_SP(NAME) #NAME " "

static const char * http_method[] = 
{
  METHOD_W_SP(OPTIONS) ,             
  METHOD_W_SP(GET),            
  METHOD_W_SP(HEAD),             
  METHOD_W_SP(POST),            
  METHOD_W_SP(PUT),             
  METHOD_W_SP(DELETE),              
  METHOD_W_SP(TRACE),              
  METHOD_W_SP(CONNECT),
  /*---*/
  NULL
};

/* 
 * HTTP-Version len: 
 */
#define HTTP_VER_LEN_W_SP (9)  
/*
 *  HTTP-Version with heading space separator 
 */
static const char http_ver[]=" HTTP/1.1";
 

/*
 * Parser of http request line:
 * Request-Line = Method SP Request-URI SP HTTP-Version CRLF
 */ 
int my_http_helper(unsigned char *pdata, int data_len)
{

  
  int i,found;
  int tmp_len;
  int len;
 
   
  /* look for method */
  len = sizeof(http_method)/sizeof(char*);
  for(i=0, found=-1; i < len &&  http_method[i]!= NULL; i++) 
  {
    tmp_len = strlen(http_method[i]);
    
    if(data_len > tmp_len && strncmp(pdata,http_method[i],tmp_len)==0 )
    {
      printk("[YS] found method %s\n",http_method[i]);
      found=i;
      break;
    }
  }
  
  if(found == -1)
  {
    printk("[YS] error http method not found \n");
    return -1;
  }

  /*look for http-version */
  len = strlen(http_ver);
  while(tmp_len + HTTP_VER_LEN_W_SP < data_len)
  {
    
    if(*(pdata + tmp_len) == http_ver[0])
    {
      
       // HTTP-version  = HTTP-name "/" DIGIT "." DIGIT
      if(strncmp(pdata + tmp_len, http_ver, len)==0)
      {
	printk("[YS] http version found %c\n",*(pdata+tmp_len+HTTP_VER_LEN_W_SP-1));

	tmp_len += HTTP_VER_LEN_W_SP;
	
	break;
      }      
    }
    else if(*(pdata + tmp_len) == '\r' || *(pdata + tmp_len) == '\n')
    {
      printk("[YS] error CR or LF inside http request \n");
      return -1;
    }
    
    ++tmp_len;
  }
  /* search for CRLF \r\n  */
  if(tmp_len + 2 < data_len &&  *(pdata + tmp_len  ) == '\r' && *(pdata + tmp_len +  1) == '\n')
  {
    printk("[YS] found http request \n");
    return 0;
  }
  
  return -1;
}
