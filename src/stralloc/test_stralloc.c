#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CuTest.h"

#include "stralloc.h"

void test_stralloc_starts(CuTest *tc) {
	stralloc sa = EMPTY_STRALLOC;
	stralloc_copys(&sa, "This is a test");
	CuAssertTrue(tc, stralloc_starts(&sa, "This"));
}

void test_stralloc_starts_equal(CuTest *tc) {
	stralloc sa = EMPTY_STRALLOC;
	stralloc_copys(&sa, "This is a test");
	CuAssertTrue(tc, stralloc_starts(&sa, "This is a test"));
}

void test_stralloc_starts_notequal(CuTest *tc) {
	stralloc sa = EMPTY_STRALLOC;
	stralloc_copys(&sa, "This is a test");
	CuAssertTrue(tc, !stralloc_starts(&sa, "this"));
}

void test_stralloc_starts_toolong(CuTest *tc) {
	stralloc sa = EMPTY_STRALLOC;
	stralloc_copys(&sa, "This is a test");
	CuAssertTrue(tc, !stralloc_starts(&sa, "This is a test!"));
}

CuSuite *stralloc_suite(void) {
	CuSuite *suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, test_stralloc_starts);
	SUITE_ADD_TEST(suite, test_stralloc_starts_equal);
	SUITE_ADD_TEST(suite, test_stralloc_starts_notequal);
	SUITE_ADD_TEST(suite, test_stralloc_starts_toolong);

	return suite;
}

void RunAllTests(void) {
	CuString *output = CuStringNew();
	CuSuite *suite = CuSuiteNew();

	CuSuiteAddSuite(suite, stralloc_suite());

	CuSuiteRun(suite);
	CuSuiteSummary(suite, output);
	CuSuiteDetails(suite, output);
	printf("%s\n", output->buffer);
}

int main(void) {
	RunAllTests();
}
