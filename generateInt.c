/*
  To generate n random integers
*/
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include <getopt.h>
//
char* strOutputFileName;
int n;
void parseArgs(int argc, char** argv);
//
int main(int argc, char** argv)
{
  int i;
  FILE* fout;
  int* buffer;
  //
  parseArgs(argc,argv);
  //
  printf("Generate %d integers, stored in %s\n",n,strOutputFileName);
  //
  buffer = (int*) malloc(sizeof(int)*n);
  //
  srand(time(NULL));
  for(0;i<n;++i) buffer[i] = rand()%100;
  //
  fout = fopen(strOutputFileName,"w");
  if(fout==NULL)
  {
    printf("Can not create %s\n",strOutputFileName);
    exit(1);
  }
  //
  fwrite(buffer,sizeof(int),n,fout);
  fclose(fout);
  printf("%s is successfully created\n",strOutputFileName);
  //
  free(strOutputFileName);
  free(buffer);
  return 0;
}
//
void parseArgs(int argc, char** argv)
{
  char c;
  int optionIndex = 0;
  struct option longOption[]=
  {
    {"output-file",1,NULL,'o'},
    {"number",1,NULL,'n'},
    {0,0,0,0}
  };
  if (argc < 5) 
  {
    printf("Wrong number of arguments\n");
    exit(1);
  }
  while((c=getopt_long(argc,argv,"n:o:",longOption,&optionIndex))!=-1)
  {
    switch(c)
    {
      case 'o':
	strOutputFileName = strdup(optarg);
	break;
      case 'n':
	n = atoi(optarg);
	break;
      default:
	printf("Bad argument %c\n",c);
	exit(1);
    }
  }    
}

