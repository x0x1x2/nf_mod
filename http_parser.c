#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>


unsigned int  my_http_helper (unsigned char *pdata, int data_len)
{
  const char * Method[] = 
  {
    "OPTIONS "  ,             
    "GET "       ,            
    "HEAD "     ,             
    "POST "     ,            
    "PUT "      ,             
    "DELETE "   ,              
    "TRACE "    ,              
    "CONNECT "   ,
    /*---*/
    NULL
  };     
  const char http_ver[]=" HTTP/";
  int i,req;
  int tmp_len;
  int len = sizeof(Method)/sizeof(char*);
  unsigned char *ptmp;
   
  /* look for method */
  for(i=0, req=-1; i < len &&  Method[i]!= NULL; i++) 
  {
    tmp_len = strlen(Method[i]);
    
    if(data_len > tmp_len && strncmp(pdata,Method[i],tmp_len)==0 )
    {
      printk("[YS] found method %s\n",Method[i]);
      req=i;
      break;
    }
  }
  
  if(req == -1)
  {
    printk("[YS] http method not found \n");
    return NF_ACCEPT;
  }
  /*look for http- keyword*/
  do{
    ptmp = (unsigned char*)memchr(pdata+tmp_len,(int)http_ver[0],data_len-tmp_len );
    
    if(ptmp == NULL) 
    {
      //printk("[YS] http version not found \n");
      return NF_ACCEPT;
    }
    printk("[YS] search http %p %c%c%c%c\n",ptmp,ptmp[0],ptmp[1],ptmp[2],ptmp[3]);
    // HTTP-version  = HTTP-name "/" DIGIT "." DIGIT
    if(strncmp(ptmp,http_ver,strlen(http_ver))!=0) 
    {
      tmp_len = ptmp-pdata+1;
    }
    else
    {
      printk("[YS] http method \n");
      break;
    }
      
  }while( data_len > tmp_len);
  
  return NF_ACCEPT;
}