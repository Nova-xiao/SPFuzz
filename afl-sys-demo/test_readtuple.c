#include<stdlib.h>
#include<stdio.h>
#include<string.h>

#define bool _Bool
static bool oldtuples[70000];

int read_tuples(){
    FILE* tuple_file = fopen("./logs/cur_tuple", "r+");
    int tuple_number;
    int hit_count;
    
    // there is an empty line in tuple file, fscanf will be stuck in the last data line
    // so we need to confirm EOF by new lines
    int last_tuple_number = 0;
    
    while (fscanf(tuple_file, "%6d:%d\n", &tuple_number, &hit_count)){
        if(tuple_number == last_tuple_number)break;
        oldtuples[tuple_number] = (hit_count!=0);
        printf("%d:%d\n", tuple_number, hit_count);
        last_tuple_number = tuple_number;
    }

    fclose(tuple_file);
    
    return tuple_number;
}

int main(){

    
    

    return 0;
}

