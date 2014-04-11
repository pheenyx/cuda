#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<getopt.h>
char* strInputFileName;
int n;
//
void parseArgs(int argc, char** argv);
void displayData(int* data, int size);
void loadData(int* data,char* fileName,int nElement);
//
int main(int argc, char** argv)
{
  int* inputData;
  //
  parseArgs(argc,argv);
  //
  inputData = (int*) malloc(sizeof(int)*n);
  //load n element from the input file
  loadData(inputData,strInputFileName,n);
  //display the input data, just use with the small data, to test
  printf("Input data:\n");
  displayData(inputData,n);
  printf("\n");
  //
  free(inputData);
  free(strInputFileName);
  //
  return 0;
}
//
void loadData(int* data,char* fileName,int nElement)
{
  FILE* fin;
  fin = fopen(fileName,"r");
  if(fin==NULL)
  {
    printf("Can not open %s\n",fileName);
    exit(1);
  }
  //
  fread(data,sizeof(int),n,fin);
  //
  fclose(fin);
}
//
void displayData(int* data, int size)
{
  int i;
  for(i=0;i<size;++i) printf("%d ",data[i]);
}
//
void parseArgs(int argc, char** argv)
{
  char c;
  int optionIndex = 0;
  struct option longOption[]=
  {
    {"input-file",1,NULL,'i'},
    {"number",1,NULL,'n'},
    {0,0,0,0}
  };
  if (argc < 5) 
  {
    printf("Wrong number of arguments\n");
    exit(1);
  }
  while((c=getopt_long(argc,argv,"n:i:s",longOption,&optionIndex))!=-1)
  {
    switch(c)
    {
      case 'i':
	strInputFileName = strdup(optarg);
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

