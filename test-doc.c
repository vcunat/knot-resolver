
#define X(comment) XXX comment YYY

X(/* function_name
	some real content
	and more documentation */)
int foo;
X(/* just function name */)


// command: cpp test-doc.c -CC | sed -n '/XXX/,/YYY/p' | grep -v '^#' | sed -e 's,XXX /\*,.. function::,' -e 's/ YYY$//' -e 's, \*/$,,'
