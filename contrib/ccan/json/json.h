/*
  Copyright (C) 2011 Joseph A. Adams (joeyadams3.14159@gmail.com)
  All rights reserved.

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#ifndef CCAN_JSON_H
#define CCAN_JSON_H

#include <lib/defines.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
	JSON_NULL,
	JSON_BOOL,
	JSON_STRING,
	JSON_NUMBER,
	JSON_ARRAY,
	JSON_OBJECT,
} JsonTag;

typedef struct JsonNode JsonNode;

struct JsonNode
{
	/* only if parent is an object or array (NULL otherwise) */
	JsonNode *parent;
	JsonNode *prev, *next;
	
	/* only if parent is an object (NULL otherwise) */
	char *key; /* Must be valid UTF-8. */
	
	JsonTag tag;
	union {
		/* JSON_BOOL */
		bool bool_;
		
		/* JSON_STRING */
		char *string_; /* Must be valid UTF-8. */
		
		/* JSON_NUMBER */
		double number_;
		
		/* JSON_ARRAY */
		/* JSON_OBJECT */
		struct {
			JsonNode *head, *tail;
		} children;
	};
};

/*** Encoding, decoding, and validation ***/

KR_EXPORT JsonNode   *json_decode         (const char *json);
KR_EXPORT char       *json_encode         (const JsonNode *node);
KR_EXPORT char       *json_encode_string  (const char *str);
KR_EXPORT char       *json_stringify      (const JsonNode *node, const char *space);
KR_EXPORT void        json_delete         (JsonNode *node);

KR_EXPORT bool        json_validate       (const char *json);

/*** Lookup and traversal ***/

KR_EXPORT JsonNode   *json_find_element   (JsonNode *array, int index);
KR_EXPORT JsonNode   *json_find_member    (JsonNode *object, const char *key);

KR_EXPORT JsonNode   *json_first_child    (const JsonNode *node);

#define json_foreach(i, object_or_array)            \
	for ((i) = json_first_child(object_or_array);   \
		 (i) != NULL;                               \
		 (i) = (i)->next)

/*** Construction and manipulation ***/

KR_EXPORT JsonNode *json_mknull(void);
KR_EXPORT JsonNode *json_mkbool(bool b);
KR_EXPORT JsonNode *json_mkstring(const char *s);
KR_EXPORT JsonNode *json_mknumber(double n);
KR_EXPORT JsonNode *json_mkarray(void);
KR_EXPORT JsonNode *json_mkobject(void);

KR_EXPORT void json_append_element(JsonNode *array, JsonNode *element);
KR_EXPORT void json_prepend_element(JsonNode *array, JsonNode *element);
KR_EXPORT void json_append_member(JsonNode *object, const char *key, JsonNode *value);
KR_EXPORT void json_prepend_member(JsonNode *object, const char *key, JsonNode *value);

KR_EXPORT void json_remove_from_parent(JsonNode *node);

/*** Debugging ***/

/*
 * Look for structure and encoding problems in a JsonNode or its descendents.
 *
 * If a problem is detected, return false, writing a description of the problem
 * to errmsg (unless errmsg is NULL).
 */
KR_EXPORT bool json_check(const JsonNode *node, char errmsg[256]);

#endif
