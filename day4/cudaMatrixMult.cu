#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <getopt.h>
#include <math.h>
#define THREADS_PER_BLOCK 4
#define BLOCK_SIZE 32
//

// Matrices are stored in row-major order:
// M(row, col) = *(M.elements + row * M.width + col)
typedef struct {
    int width;
    int height;
    int* elements;
    int stride;
} Matrix;


char* strInputFileName;
int N;
int isSerial = 0;
int verbose = 0;
//
void checkCUDAError(const char *msg);
void parseArgs(int argc, char** argv);
void displayData(Matrix A);
void loadData(Matrix A,char* fileName,int nElement);
void cudaFunction(const Matrix A, const Matrix B, Matrix C);
void serialFunction(const Matrix A, const Matrix B, Matrix C);


// Get a matrix element
__device__ int GetElement(const Matrix A, int row, int col) {
    return A.elements[row * A.stride + col];
}
// Set a matrix element
__device__ void SetElement(Matrix A, int row, int col, int value) {
    A.elements[row * A.stride + col] = value;
}
// Get the BLOCK_SIZExBLOCK_SIZE sub-matrix Asub of A that is
// located col sub-matrices to the right and row sub-matrices down
// from the upper-left corner of A
__device__ Matrix GetSubMatrix(Matrix A, int row, int col, int N) {
    Matrix Asub;
    Asub.width = N;
    Asub.height = N;
    Asub.stride = A.stride;
    Asub.elements = &A.elements[A.stride * N * row + N * col];
    return Asub;
}

// Matrix multiplication kernel called by MatMul()
__global__ void MatMulKernel(Matrix A, Matrix B, Matrix C, int N) {
    extern __shared__ int data[];
    // Block row and column
    int blockRow = blockIdx.y;
    int blockCol = blockIdx.x;
    // Each thread block computes one sub-matrix Csub of C
    Matrix Csub = GetSubMatrix(C, blockRow, blockCol, N);
    // Each thread computes one element of Csub
    // by accumulating results into Cvalue
    int Cvalue = 0;
    // Thread row and column within Csub
    int row = threadIdx.y;
    int col = threadIdx.x;
    int tid = blockDim.y*row+col;
    // Loop over all the sub-matrices of A and B that are
    // required to compute Csub
    // Multiply each pair of sub-matrices together
    // and accumulate the results
    for (int m = 0; m < (A.width / N); ++m) {
        // Get sub-matrix Asub of A
        Matrix Asub = GetSubMatrix(A, blockRow, m, N);
        // Get sub-matrix Bsub of B
        Matrix Bsub = GetSubMatrix(B, m, blockCol, N);
        // Shared memory used to store Asub and Bsub respectively
        int* As = &data[0];
        int* Bs = &data[blockDim.x*blockDim.y];
        // Load Asub and Bsub from device memory to shared memory
        // Each thread loads one element of each sub-matrix
        As[tid] = GetElement(Asub, row, col);
        Bs[tid] = GetElement(Bsub, row, col);
        // Synchronize to make sure the sub-matrices are loaded
        // before starting the computation
        __syncthreads();
        // Multiply Asub and Bsub together
        for (int e = 0; e < N; ++e){
            printf("m:%i tid:%i  A[%i]=%i * B[%i]=%i\n",m,tid,blockDim.y*row+e,As[blockDim.y*row+e],blockDim.x*e+col,Bs[blockDim.x*e+col]);
            Cvalue += As[blockDim.y*row+e] * Bs[blockDim.x*e+col];
        }
        // Synchronize to make sure that the preceding
        // computation is done before loading two new
        // sub-matrices of A and B in the next iteration
        __syncthreads();
    }
    // Write Csub to device memory
    // Each thread writes one element
    SetElement(Csub, row, col, Cvalue);
}




int main(int argc, char** argv)
{
    
    Matrix A, B, C;
    //
    parseArgs(argc,argv);
    //find the next power of 2 to allocate the array
    int nextPowOf2;
    if (!(N==0) && !(N & (N-1))){
        nextPowOf2 = N;
    } else {
        nextPowOf2 = (int)pow(2,ceil(log2((double)N)));
    }
    
    A.height = N;
    A.width = N;
    A.elements = (int*)malloc(A.width * A.height * sizeof(int));

    B.height = N;
    B.width = N;
    B.elements = (int*)malloc(B.width * B.height * sizeof(int));
    
    C.height = N;
    C.width = N;
    C.elements = (int*)malloc(C.width * C.height * sizeof(int));
    
    //load n*n elements from the input file
    loadData(A,strInputFileName,N*N);
    loadData(B,strInputFileName,N*N);
    //display the input data, just use with the small data, to test
    if (verbose) {
        printf("Input data A:\n");
        displayData(A);
        printf("Input data B:\n");
        displayData(B);
    }
    //
    if(isSerial == 0)
    {
        printf("Running the CUDA implementation\n");
        cudaFunction(A,B,C);
        //
    }
    else
    {
        printf("Running the serial implementation\n");
        serialFunction(A,B,C);
    }
    //
    free(strInputFileName);
    //
    return 0;
}
//
// Matrix multiplication - Host code
// Matrix dimensions are assumed to be multiples of BLOCK_SIZE
void cudaFunction(const Matrix A, const Matrix B, Matrix C)
{
    //the CUDA implementation here 
    cudaEvent_t start, stop;
    float elapsedTime;
    size_t size;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    //
    
    
    
    
    cudaEventRecord(start,0);
    // Load A and B to device memory
    Matrix d_A;
    d_A.width = d_A.stride = A.width;
    d_A.height = A.height;
    size = A.width * A.height * sizeof(int);
    cudaMalloc(&d_A.elements, size);
    checkCUDAError("cudaMalloc A");

    cudaMemcpy(d_A.elements, A.elements, size, cudaMemcpyHostToDevice);
    checkCUDAError("cudaMemcpy: host to device A");
    
    Matrix d_B;
    d_B.width = d_B.stride = B.width;
    d_B.height = B.height;
    size = B.width * B.height * sizeof(int);
    cudaMalloc(&d_B.elements, size);
    checkCUDAError("cudaMalloc B");
    
    cudaMemcpy(d_B.elements, B.elements, size, cudaMemcpyHostToDevice);
    checkCUDAError("cudaMemcpy: host to device B");

    // Allocate C in device memory
    Matrix d_C;
    d_C.width = d_C.stride = C.width;
    d_C.height = C.height;
    size = C.width * C.height * sizeof(int);
    cudaMalloc(&d_C.elements, size);
    checkCUDAError("cudaMalloc C");

    // Invoke kernel
    int n = (N < BLOCK_SIZE ? N : BLOCK_SIZE);
    dim3 dimBlock(n,n);
    dim3 dimGrid(B.width / dimBlock.x, A.height / dimBlock.y);
    printf("dimBlock %i, %i\n",n,n);
    printf("dimGrid %i, %i\n",B.width / dimBlock.x, A.height / dimBlock.y);
    int sharedSize = 2*dimBlock.x*dimBlock.x*sizeof(int);
    MatMulKernel<<<dimGrid, dimBlock, sharedSize>>>(d_A, d_B, d_C, n);
    cudaThreadSynchronize();
    checkCUDAError("kernel lauching");
    // Read C from device memory
    cudaMemcpy(C.elements, d_C.elements, size, cudaMemcpyDeviceToHost);
    checkCUDAError("Copy C off device");
    
    //stop recorder and print time
    cudaEventRecord(stop,0);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&elapsedTime,start,stop);
    printf("the scan result is :\n");
    displayData(C);
    printf("Elapsed time is: %f\n",elapsedTime);
    //
    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    // Free device memory
    cudaFree(d_A.elements);
    cudaFree(d_B.elements);
    cudaFree(d_C.elements);
}
//
void serialFunction(const Matrix A,const Matrix B, Matrix C)
{
    cudaEvent_t start, stop;
    float elapsedTime;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start,0);
    //the serial implementation here
    for(int i = 0; i < A.width; ++i)
        for(int j = 0; j < B.height; ++j)
            for(int k = 0; k < B.height; ++k)
                C.elements[i*A.width + j] += A.elements[i*A.width + k] * B.elements[k*B.height+j];
    cudaEventRecord(stop,0);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&elapsedTime,start,stop);
    printf("the serial scan result is :\n");
    displayData(C);
    printf("Elapsed time is: %f\n",elapsedTime);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

}
//
void loadData(Matrix A,char* fileName,int nElement)
{
    int* data = (int*)malloc(nElement * sizeof(int));
    FILE* fin;
    fin = fopen(fileName,"r");
    if(fin==NULL)
    {
        printf("Can not open %s\n",fileName);
        exit(1);
    }
    //
    fread(data,sizeof(int),nElement,fin);
    //
    fclose(fin);

    for(int i = 0; i < A.height; i++)
        for(int j = 0; j < A.width; j++)
            A.elements[i*A.width + j] = data[i*A.width + j];
}
//
void displayData(Matrix A)
{
    for(int i = 0; i < A.height; i++){
        for(int j = 0; j < A.width; j++)
            printf("%i ", A.elements[i*A.width + j]);
        printf("\n");
    }
    printf("\n");
}
//
//function to check cuda error, cited from 
//http://www.drdobbs.com/parallel/cuda-supercomputing-for-the-masses-part/207603131?pgno=2
void checkCUDAError(const char *msg)
{
    cudaError_t err = cudaGetLastError();
    if( cudaSuccess != err) 
    {
        fprintf(stderr, "Cuda error: %s: %s.\n", msg, 
                cudaGetErrorString( err) );
        exit(EXIT_FAILURE);
    }                         
}
void parseArgs(int argc, char** argv)
{
    char c;
    int optionIndex = 0;
    struct option longOption[]=
    {
        {"inputfile",1,NULL,'i'},
        {"number",1,NULL,'n'},
        {"serial",1,NULL,'s'},
        {"verbose",1,NULL,'v'},
        {0,0,0,0}
    };
    if (argc < 5) 
    {
        printf("Wrong number of arguments\n");
        exit(1);
    }
    while((c=getopt_long(argc,argv,"n:i:sv",longOption,&optionIndex))!=-1)
    {
        switch(c)
        {
            case 'i':
                strInputFileName = strdup(optarg);
                break;
            case 'n':
                N = atoi(optarg);
                break;
            case 's':
                isSerial = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                printf("Bad argument %c\n",c);
                exit(1);
        }
    }    
}

