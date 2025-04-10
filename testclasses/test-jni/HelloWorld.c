#include <jni.h>
#include <stdio.h>
#include "HelloWorld.h"

JNIEXPORT void JNICALL
Java_HelloWorld_print(JNIEnv *env, jobject obj) {
    /*while(1) {}*/
    printf("here %p\n", env);
    /*while(1) {}*/
    jint version = (*env)->GetVersion(env);
    printf("version %i\n", version);
    jclass class = (*env)->GetObjectClass(env, obj);
    printf("class\n");
    jfieldID fld = (*env)->GetFieldID(env, class, "number", "I");
    printf("fld\n");
    jint val = (*env)->GetIntField(env, obj, fld);
	printf("Hello world!\nnumber = %i", val);
	return;
}
