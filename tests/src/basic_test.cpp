#include <cstdio>
#include <iostream>

const char* names[4] = { "hell", "ow", "world", "dl" };

int arr[5] = { 1,2,3,4,5 };
int* arr_ptr = arr;

int main(int argc, char* argv[]);


struct Node {
    int val;
    struct Node* left;
    struct Node* right;
};

struct Node n2 {
    65, NULL, NULL
};
struct Node n3 {
    1, NULL, NULL
};
struct Node n4 {
    86, &n3, NULL
};

struct Node n1 {
    90, &n4, &n2
};

int main(int argc, char* argv[])
{

    std::cout << "Hello, world!" << std::endl;
    std::cout << names[0] << std::endl;
    std::cout << arr_ptr[1] << std::endl;
    std::cout << n1.left->left->val << std::endl;
}