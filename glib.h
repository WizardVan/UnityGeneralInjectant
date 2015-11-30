#pragma once
#include "stdafx.h"

typedef int            gboolean;
typedef int            gint;
typedef unsigned int   guint;
typedef short          gshort;
typedef unsigned short gushort;
typedef long           glong;
typedef unsigned long  gulong;
typedef void *         gpointer;
typedef const void *   gconstpointer;
typedef char           gchar;
typedef unsigned char  guchar;

typedef __int8				gint8;
typedef unsigned __int8		guint8;
typedef __int16				gint16;
typedef unsigned __int16	guint16;
typedef __int32				gint32;
typedef unsigned __int32	guint32;
typedef __int64				gint64;
typedef unsigned __int64	guint64;
typedef float				gfloat;
typedef double				gdouble;
typedef unsigned __int16	gunichar2;

typedef unsigned long gsize;

typedef struct _GSList GSList;
struct _GSList {
	gpointer data;
	GSList *next;
};


typedef guint(*GHashFunc)      (gconstpointer key);
typedef gboolean(*GEqualFunc)     (gconstpointer a, gconstpointer b);
typedef void(*GDestroyNotify) (gpointer data);

/* This macro is used to make bit field packing compatible with MSVC */
#if defined(_MSC_VER) && defined(PLATFORM_IPHONE_XCOMP)
#   define USE_UINT8_BIT_FIELD(type, field) guint8 field 
#else
#   define USE_UINT8_BIT_FIELD(type, field) type field
#endif

