#pragma once
#include "stdafx.h"
#include "glib.h"
#include "blob.h"

#define MONO_PUBLIC_KEY_TOKEN_LENGTH	17

#ifndef MONO_ZERO_LEN_ARRAY
#ifdef __GNUC__
#define MONO_ZERO_LEN_ARRAY 0
#else
#define MONO_ZERO_LEN_ARRAY 1
#endif
#endif

#define MONO_JIT_INFO_TABLE_CHUNK_SIZE		64

typedef struct _MonoMemPool MonoMemPool;
typedef struct _GHashTable GHashTable;
typedef struct _MonoImage MonoImage;
typedef struct _MonoTableInfo MonoTableInfo;
typedef struct _MonoAssembly MonoAssembly;
typedef struct _MonoDllMap MonoDllMap;
typedef gpointer(*MonoInternalHashKeyExtractFunc) (gpointer value);
typedef gpointer* (*MonoInternalHashNextValueFunc) (gpointer value);
typedef struct _MonoInternalHashTable MonoInternalHashTable;
typedef struct _MonoPropertyHash MonoPropertyHash;
typedef struct _Slot Slot;
typedef struct _MonoDomain MonoDomain;
typedef struct _MonoCodeManager MonoCodeManager;
typedef struct _CodeChunck CodeChunk;
typedef struct _MonoThreadsSync MonoThreadsSync;
typedef struct _MonoClass MonoClass;
typedef struct _MonoClassField MonoClassField;
typedef struct _MonoMethod MonoMethod;
typedef struct _MonoMethodSignature MonoMethodSignature;
typedef struct _MonoType MonoType;
typedef struct _MonoArrayType MonoArrayType;
typedef struct _MonoGenericParam MonoGenericParam;
typedef struct _MonoGenericContainer MonoGenericContainer;
typedef struct _MonoGenericContext MonoGenericContext;
typedef struct _MonoGenericInst MonoGenericInst;
typedef struct _MonoGenericClass MonoGenericClass;
typedef struct _MonoProperty MonoProperty;
typedef struct _MonoEvent MonoEvent;
typedef struct _GList GList;
typedef gpointer MonoRuntimeGenericContext;
typedef guchar MonoBoolean;
typedef guint32 mono_array_size_t;
typedef gint32 mono_array_lower_bound_t;
typedef struct _MonoAppDomain MonoAppDomain;
typedef struct _MonoAppContext MonoAppContext;
typedef struct _MonoException MonoException;
typedef struct _MonoGHashTable  MonoGHashTable;
typedef struct _MonoJitInfoTable MonoJitInfoTable;
typedef struct _MonoJitInfoTableChunk MonoJitInfoTableChunk;
typedef struct _MonoJitInfo MonoJitInfo;
typedef struct _MonoBitSet MonoBitSet;
typedef struct _MonoObject MonoObject;
typedef gboolean(*MonoCoreClrPlatformCB) (const char *image_name);
typedef struct _MonoVTable MonoVTable;
typedef struct _MonoAppDomainSetup MonoAppDomainSetup;
typedef struct _MonoStreamHeader MonoStreamHeader;
typedef struct _MonoAssemblyName MonoAssemblyName;
typedef struct _MonoThunkFreeList MonoThunkFreeList;
typedef struct _MonoMarshalType MonoMarshalType;
typedef struct _MonoGenericParamFull MonoGenericParamFull;
typedef struct _MonoGenericParamInfo MonoGenericParamInfo;
typedef struct _MonoCustomMod MonoCustomMod;
typedef struct _MonoMarshalField MonoMarshalField;
typedef struct _MonoMarshalSpec MonoMarshalSpec;
typedef enum _MonoMarshalNative MonoMarshalNative;
typedef enum _MonoMarshalVariant MonoMarshalVariant;
typedef struct _MonoClassRuntimeInfo MonoClassRuntimeInfo;
typedef struct _MonoClassExt MonoClassExt;
typedef struct _MonoFieldDefaultValue MonoFieldDefaultValue;
typedef struct _MonoString MonoString;
typedef struct _MonoArray MonoArray;
typedef struct _MonoArrayBounds MonoArrayBounds;
typedef struct _MonoMarshalByRefObject MonoMarshalByRefObject;
typedef enum _MonoGHashGCType MonoGHashGCType;
typedef struct _MonoJitExceptionInfo MonoJitExceptionInfo;
typedef enum _MonoImageOpenStatus MonoImageOpenStatus;
typedef enum _MonoSecurityMode MonoSecurityMode;

struct _MonoBitSet{
	gsize size;
	gsize flags;
	gsize data[MONO_ZERO_LEN_ARRAY];
} ;

struct _MonoStreamHeader{
	const char* data;
	guint32  size;
};

struct _MonoTableInfo {
	const char *base;
	guint       rows : 24;
	guint       row_size : 8;

	/*
	* Tables contain up to 9 columns and the possible sizes of the
	* fields in the documentation are 1, 2 and 4 bytes.  So we
	* can encode in 2 bits the size.
	*
	* A 32 bit value can encode the resulting size
	*
	* The top eight bits encode the number of columns in the table.
	* we only need 4, but 8 is aligned no shift required.
	*/
	guint32   size_bitfield;
};

struct _MonoAssemblyName{
	const char *name;
	const char *culture;
	const char *hash_value;
	const guint8* public_key;
	// string of 16 hex chars + 1 NULL
	guchar public_key_token[MONO_PUBLIC_KEY_TOKEN_LENGTH];
	guint32 hash_alg;
	guint32 hash_len;
	guint32 flags;
	guint16 major, minor, build, revision;
};

struct _MonoDllMap {
	char *dll;
	char *target;
	char *func;
	char *target_func;
	MonoDllMap *next;
};

struct _Slot {
	gpointer key;
	gpointer value;
	Slot    *next;
};

struct _MonoThunkFreeList {
	guint32 size;
	int length;		/* only valid for the wait list */
	MonoThunkFreeList *next;
};

struct _CodeChunck {
	char *data;
	int pos;
	int size;
	CodeChunk *next;
	unsigned int flags : 8;
	/* this number of bytes is available to resolve addresses far in memory */
	unsigned int bsize : 24;
};

struct _MonoCodeManager {
	int dynamic;
	int read_only;
	CodeChunk *current;
	CodeChunk *full;
};

struct _MonoThreadsSync
{
	gsize owner;			/* thread ID */
	guint32 nest;
#ifdef HAVE_MOVING_COLLECTOR
	gint32 hash_code;
#endif
	volatile gint32 entry_count;
	HANDLE entry_sem;
	GSList *wait_list;
	void *data;
};

struct _GList {
	gpointer data;
	GList *next;
	GList *prev;
};

struct _MonoInternalHashTable
{
	GHashFunc hash_func;
	MonoInternalHashKeyExtractFunc key_extract;
	MonoInternalHashNextValueFunc next_value;
	gint size;
	gint num_entries;
	gpointer *table;
};

struct _MonoVTable {
	MonoClass  *klass;
	/*
	* According to comments in gc_gcj.h, this should be the second word in
	* the vtable.
	*/
	void *gc_descr;
	MonoDomain *domain;  /* each object/vtable belongs to exactly one domain */
	gpointer    data; /* to store static class data */
	gpointer    type; /* System.Type type for klass */
	guint8     *interface_bitmap;
	guint16     max_interface_id;
	guint8      rank;
	USE_UINT8_BIT_FIELD(guint, remote      : 1); /* class is remotely activated */
	USE_UINT8_BIT_FIELD(guint, initialized : 1); /* cctor has been run */
	USE_UINT8_BIT_FIELD(guint, init_failed : 1); /* cctor execution failed */
	guint32     imt_collisions_bitmap;
	MonoRuntimeGenericContext *runtime_generic_context;
	/* do not add any fields after vtable, the structure is dynamically extended */
	gpointer    vtable[MONO_ZERO_LEN_ARRAY];
};

struct _MonoObject{
	MonoVTable *vtable;
	MonoThreadsSync *synchronisation;
} ;

struct _MonoAppDomainSetup{
	MonoObject object;
	MonoString *application_base;
	MonoString *application_name;
	MonoString *cache_path;
	MonoString *configuration_file;
	MonoString *dynamic_base;
	MonoString *license_file;
	MonoString *private_bin_path;
	MonoString *private_bin_path_probe;
	MonoString *shadow_copy_directories;
	MonoString *shadow_copy_files;
	MonoBoolean publisher_policy;
	MonoBoolean path_changed;
	int loader_optimization;
	MonoBoolean disallow_binding_redirects;
	MonoBoolean disallow_code_downloads;
	MonoObject *activation_arguments; /* it is System.Object in 1.x, ActivationArguments in 2.0 */
	MonoObject *domain_initializer;
	MonoArray *domain_initializer_args;
	MonoObject *application_trust; /* it is System.Object in 1.x, ApplicationTrust in 2.0 */
	MonoBoolean disallow_appbase_probe;
	MonoArray *configuration_bytes;
} ;


#ifdef MALLOC_ALLOCATION
typedef struct _Chunk {
	struct _Chunk *next;
	guint32 size;
} Chunk;

struct _MonoMemPool {
	Chunk *chunks;
	guint32 allocated;
};
#else
struct _MonoMemPool {
	MonoMemPool *next;
	gint rest;
	guint8 *pos, *end;
	guint32 size;
	union {
		double pad; /* to assure proper alignment */
		guint32 allocated;
	} d;
};
#endif



struct _MonoAssembly {
	/*
	* The number of appdomains which have this assembly loaded plus the number of
	* assemblies referencing this assembly through an entry in their image->references
	* arrays. The later is needed because entries in the image->references array
	* might point to assemblies which are only loaded in some appdomains, and without
	* the additional reference, they can be freed at any time.
	* The ref_count is initially 0.
	*/
	int ref_count; /* use atomic operations only */
	char *basedir;
	MonoAssemblyName aname;
	MonoImage *image;
	GSList *friend_assembly_names; /* Computed by mono_assembly_load_friends () */
	guint8 friend_assembly_names_inited;
	guint8 in_gac;
	guint8 dynamic;
	guint8 corlib_internal;
	gboolean ref_only;
	/* security manager flags (one bit is for lazy initialization) */
	guint32 ecma : 2;		/* Has the ECMA key */
	guint32 aptc : 2;		/* Has the [AllowPartiallyTrustedCallers] attributes */
	guint32 fulltrust : 2;	/* Has FullTrust permission */
	guint32 unmanaged : 2;	/* Has SecurityPermissionFlag.UnmanagedCode permission */
	guint32 skipverification : 2;	/* Has SecurityPermissionFlag.SkipVerification permission */
};

struct _MonoImage {
	/*
	* The number of assemblies which reference this MonoImage though their 'image'
	* field plus the number of images which reference this MonoImage through their
	* 'modules' field, plus the number of threads holding temporary references to
	* this image between calls of mono_image_open () and mono_image_close ().
	*/
	int   ref_count;
	void *raw_data_handle;
	char *raw_data;
	guint32 raw_data_len;
	guint8 raw_buffer_used : 1;
	guint8 raw_data_allocated : 1;

#ifdef USE_COREE
	/* Module was loaded using LoadLibrary. */
	guint8 is_module_handle : 1;

	/* Module entry point is _CorDllMain. */
	guint8 has_entry_point : 1;
#endif

	/* Whenever this is a dynamically emitted module */
	guint8 dynamic : 1;

	/* Whenever this is a reflection only image */
	guint8 ref_only : 1;

	/* Whenever this image contains uncompressed metadata */
	guint8 uncompressed_metadata : 1;

	guint8 checked_module_cctor : 1;
	guint8 has_module_cctor : 1;

	guint8 idx_string_wide : 1;
	guint8 idx_guid_wide : 1;
	guint8 idx_blob_wide : 1;

	/* Whenever this image is considered as platform code for the CoreCLR security model */
	guint8 core_clr_platform_code : 1;

	char *name;
	const char *assembly_name;
	const char *module_name;
	char *version;
	gint16 md_version_major, md_version_minor;
	char *guid;
	void *image_info;
	MonoMemPool         *mempool; /*protected by the image lock*/

	char                *raw_metadata;

	MonoStreamHeader     heap_strings;
	MonoStreamHeader     heap_us;
	MonoStreamHeader     heap_blob;
	MonoStreamHeader     heap_guid;
	MonoStreamHeader     heap_tables;

	const char          *tables_base;

	/**/
	MonoTableInfo        tables[MONO_TABLE_NUM];

	/*
	* references is initialized only by using the mono_assembly_open
	* function, and not by using the lowlevel mono_image_open.
	*
	* It is NULL terminated.
	*/
	MonoAssembly **references;

	MonoImage **modules;
	guint32 module_count;
	gboolean *modules_loaded;

	MonoImage **files;

	gpointer aot_module;

	/*
	* The Assembly this image was loaded from.
	*/
	MonoAssembly *assembly;

	/*
	* Indexed by method tokens and typedef tokens.
	*/
	GHashTable *method_cache; /*protected by the image lock*/
	MonoInternalHashTable class_cache;

	/* Indexed by memberref + methodspec tokens */
	GHashTable *methodref_cache; /*protected by the image lock*/

	/*
	* Indexed by fielddef and memberref tokens
	*/
	GHashTable *field_cache;

	/* indexed by typespec tokens. */
	GHashTable *typespec_cache;
	/* indexed by token */
	GHashTable *memberref_signatures;
	GHashTable *helper_signatures;

	/* Indexed by blob heap indexes */
	GHashTable *method_signatures;

	/*
	* Indexes namespaces to hash tables that map class name to typedef token.
	*/
	GHashTable *name_cache;  /*protected by the image lock*/

	/*
	* Indexed by MonoClass
	*/
	GHashTable *array_cache;
	GHashTable *ptr_cache;

	GHashTable *szarray_cache;
	/* This has a separate lock to improve scalability */
	CRITICAL_SECTION szarray_cache_lock;

	/*
	* indexed by MonoMethodSignature
	*/
	GHashTable *delegate_begin_invoke_cache;
	GHashTable *delegate_end_invoke_cache;
	GHashTable *delegate_invoke_cache;
	GHashTable *runtime_invoke_cache;

	/*
	* indexed by SignatureMethodPair
	*/
	GHashTable *delegate_abstract_invoke_cache;

	/*
	* indexed by MonoMethod pointers
	*/
	GHashTable *runtime_invoke_direct_cache;
	GHashTable *runtime_invoke_vcall_cache;
	GHashTable *managed_wrapper_cache;
	GHashTable *native_wrapper_cache;
	GHashTable *native_wrapper_aot_cache;
	GHashTable *remoting_invoke_cache;
	GHashTable *synchronized_cache;
	GHashTable *unbox_wrapper_cache;
	GHashTable *cominterop_invoke_cache;
	GHashTable *cominterop_wrapper_cache; /* LOCKING: marshal lock */
	GHashTable *thunk_invoke_cache;

	/*
	* indexed by MonoClass pointers
	*/
	GHashTable *ldfld_wrapper_cache;
	GHashTable *ldflda_wrapper_cache;
	GHashTable *stfld_wrapper_cache;
	GHashTable *isinst_cache;
	GHashTable *castclass_cache;
	GHashTable *proxy_isinst_cache;
	GHashTable *rgctx_template_hash; /* LOCKING: templates lock */

	/*
	* indexed by token and MonoGenericContext pointer
	*/
	GHashTable *generic_class_cache;

	/* Contains rarely used fields of runtime structures belonging to this image */
	MonoPropertyHash *property_hash;

	void *reflection_info;

	/*
	* user_info is a public field and is not touched by the
	* metadata engine
	*/
	void *user_info;

	/* dll map entries */
	MonoDllMap *dll_map;

	/* interfaces IDs from this image */
	MonoBitSet *interface_bitset;

	GSList *reflection_info_unregister_classes;

	/*
	* No other runtime locks must be taken while holding this lock.
	* It's meant to be used only to mutate and query structures part of this image.
	*/
	CRITICAL_SECTION    lock;
};

struct _MonoPropertyHash {
	/* We use one hash table per property */
	GHashTable *hashes;
};

struct _GHashTable {
	GHashFunc      hash_func;
	GEqualFunc     key_equal_func;

	Slot **table;
	int   table_size;
	int   in_use;
	int   threshold;
	int   last_rehash;
	GDestroyNotify value_destroy_func, key_destroy_func;
};


struct _MonoDomain {
	/*
	* This lock must never be taken before the loader lock,
	* i.e. if both are taken by the same thread, the loader lock
	* must taken first.
	*/
	CRITICAL_SECTION    lock;
	MonoMemPool        *mp;
	MonoCodeManager    *code_mp;
	/*
	* keep all the managed objects close to each other for the precise GC
	* For the Boehm GC we additionally keep close also other GC-tracked pointers.
	*/
#define MONO_DOMAIN_FIRST_OBJECT setup
	MonoAppDomainSetup *setup;
	MonoAppDomain      *domain;
	MonoAppContext     *default_context;
	MonoException      *out_of_memory_ex;
	MonoException      *null_reference_ex;
	MonoException      *stack_overflow_ex;
	MonoException      *divide_by_zero_ex;
	/* typeof (void) */
	MonoObject         *typeof_void;
	/*
	* The fields between FIRST_GC_TRACKED and LAST_GC_TRACKED are roots, but
	* not object references.
	*/
#define MONO_DOMAIN_FIRST_GC_TRACKED env
	MonoGHashTable     *env;
	MonoGHashTable     *ldstr_table;
	/* hashtables for Reflection handles */
	MonoGHashTable     *type_hash;
	MonoGHashTable     *refobject_hash;
	/* a GC-tracked array to keep references to the static fields of types */
	gpointer           *static_data_array;
	/* maps class -> type initialization exception object */
	MonoGHashTable    *type_init_exception_hash;
	/* maps delegate trampoline addr -> delegate object */
	MonoGHashTable     *delegate_hash_table;
#define MONO_DOMAIN_LAST_GC_TRACKED delegate_hash_table
	guint32            state;
	/* Needed by Thread:GetDomainID() */
	gint32             domain_id;
	gint32             shadow_serial;
	unsigned char      inet_family_hint; // used in socket-io.c as a cache
	GSList             *domain_assemblies;
	MonoAssembly       *entry_assembly;
	char               *friendly_name;
	GHashTable         *class_vtable_hash;
	/* maps remote class key -> MonoRemoteClass */
	GHashTable         *proxy_vtable_hash;
	/* Protected by 'jit_code_hash_lock' */
	MonoInternalHashTable jit_code_hash;
	CRITICAL_SECTION    jit_code_hash_lock;
	int		    num_jit_info_tables;
	MonoJitInfoTable *
		volatile          jit_info_table;
	GSList		   *jit_info_free_queue;
	/* Used when loading assemblies */
	gchar **search_path;
	gchar *private_bin_path;

	/* Used by remoting proxies */
	MonoMethod         *create_proxy_for_type_method;
	MonoMethod         *private_invoke_method;
	/* Used to store offsets of thread and context static fields */
	GHashTable         *special_static_fields;
	/*
	* This must be a GHashTable, since these objects can't be finalized
	* if the hashtable contains a GC visible reference to them.
	*/
	GHashTable         *finalizable_objects_hash;
#ifndef HAVE_SGEN_GC
	/* Maps MonoObjects to a GSList of WeakTrackResurrection GCHandles pointing to them */
	GHashTable         *track_resurrection_objects_hash;
	/* Maps WeakTrackResurrection GCHandles to the MonoObjects they point to */
	GHashTable         *track_resurrection_handles_hash;
#endif
	/* Protects the three hashes above */
	CRITICAL_SECTION   finalizable_objects_hash_lock;
	/* Used when accessing 'domain_assemblies' */
	CRITICAL_SECTION    assemblies_lock;

	GHashTable	   *method_rgctx_hash;

	GHashTable	   *generic_virtual_cases;
	MonoThunkFreeList **thunk_free_lists;

	/* Hashing class attributes as a lookup optimization */
	GHashTable	*class_custom_attributes;

	/* Information maintained by the JIT engine */
	gpointer runtime_info;

	/*thread pool jobs, used to coordinate shutdown.*/
	int					threadpool_jobs;
	HANDLE				cleanup_semaphore;

	/* Contains the compiled runtime invoke wrapper used by finalizers */
	gpointer            finalize_runtime_invoke;

	/* Contains the compiled runtime invoke wrapper used by async resylt creation to capture thread context*/
	gpointer            capture_context_runtime_invoke;

	/* Contains the compiled method used by async resylt creation to capture thread context*/
	gpointer            capture_context_method;

	/* Used by socket-io.c */
	/* These are domain specific, since the assembly can be unloaded */
	MonoImage *socket_assembly;
	MonoClass *sockaddr_class;
	MonoClassField *sockaddr_data_field;

	/* unity specific, cache the class for each static field */
	/* a GC-tracked array to keep references to the static fields of types */
	MonoClass           **static_data_class_array;
};







struct _MonoClassField {
	/* Type of the field */
	MonoType        *type;

	const char      *name;

	/* Type where the field was defined */
	MonoClass       *parent;

	/*
	* Offset where this field is stored; if it is an instance
	* field, it's the offset from the start of the object, if
	* it's static, it's from the start of the memory chunk
	* allocated for statics for the class.
	* For special static fields, this is set to -1 during vtable construction.
	*/
	int              offset;
};

struct _MonoMethod {
	guint16 flags;  /* method flags */
	guint16 iflags; /* method implementation flags */
	guint32 token;
	MonoClass *klass;
	MonoMethodSignature *signature;
	/* name is useful mostly for debugging */
	const char *name;
	/* this is used by the inlining algorithm */
	unsigned int inline_info : 1;
	unsigned int inline_failure : 1;
	unsigned int wrapper_type : 5;
	unsigned int string_ctor : 1;
	unsigned int save_lmf : 1;
	unsigned int dynamic : 1; /* created & destroyed during runtime */
	unsigned int is_generic : 1; /* whenever this is a generic method definition */
	unsigned int is_inflated : 1; /* whether we're a MonoMethodInflated */
	unsigned int skip_visibility : 1; /* whenever to skip JIT visibility checks */
	unsigned int verification_success : 1; /* whether this method has been verified successfully.*/
	/* TODO we MUST get rid of this field, it's an ugly hack nobody is proud of. */
	unsigned int is_mb_open : 1;		/* This is the fully open instantiation of a generic method_builder. Worse than is_tb_open, but it's temporary */
	signed int slot : 17;

	/*
	* If is_generic is TRUE, the generic_container is stored in image->property_hash,
	* using the key MONO_METHOD_PROP_GENERIC_CONTAINER.
	*/
};

struct _MonoMethodSignature {
	unsigned int  hasthis : 1;
	unsigned int  explicit_this : 1;
	unsigned int  call_convention : 6;
	unsigned int  pinvoke : 1;
	unsigned int  ref_count : 23;
	guint16       param_count;
	gint16        sentinelpos;
	unsigned int  generic_param_count : 30;
	unsigned int  is_inflated : 1;
	unsigned int  has_type_parameters : 1;
	MonoType     *ret;
	MonoType     *params[MONO_ZERO_LEN_ARRAY];
};


struct _MonoArrayType {
	MonoClass *eklass;
	guint8 rank;
	guint8 numsizes;
	guint8 numlobounds;
	int *sizes;
	int *lobounds;
};

struct _MonoGenericParam {
	MonoGenericContainer *owner;	/* Type or method this parameter was defined in. */
	guint16 num;
	/*
	* If owner is NULL, or owner is 'owned' by this gparam,
	* then this is the image whose mempool this struct was allocated from.
	* The second case happens for gparams created in
	* mono_reflection_initialize_generic_parameter ().
	*/
	MonoImage *image;
};


struct _MonoGenericContext {
	/* The instantiation corresponding to the class generic parameters */
	MonoGenericInst *class_inst;
	/* The instantiation corresponding to the method generic parameters */
	MonoGenericInst *method_inst;
};

struct _MonoGenericInst {
	guint id;			/* unique ID for debugging */
	guint type_argc : 22;	/* number of type arguments */
	guint is_open : 1;	/* if this is an open type */
	MonoType *type_argv[MONO_ZERO_LEN_ARRAY];
};


struct _MonoGenericParamInfo{
	MonoClass *pklass;		/* The corresponding `MonoClass'. */
	const char *name;
	guint16 flags;
	guint32 token;
	MonoClass** constraints; /* NULL means end of list */
} ;

struct _MonoGenericClass {
	MonoClass *container_class;	/* the generic type definition */
	MonoGenericContext context;	/* a context that contains the type instantiation doesn't contain any method instantiation */
	guint is_dynamic : 1;		/* We're a MonoDynamicGenericClass */
	guint is_tb_open : 1;		/* This is the fully open instantiation for a type_builder. Quite ugly, but it's temporary.*/
	MonoClass *cached_class;	/* if present, the MonoClass corresponding to the instantiation.  */
};

struct _MonoCustomMod{
	unsigned int required : 1;
	unsigned int token : 31;
} ;

struct _MonoMarshalField{
	MonoClassField *field;
	guint32 offset;
	MonoMarshalSpec *mspec;
} ;

struct _MonoMarshalSpec{
	MonoMarshalNative native;
	union {
		struct {
			MonoMarshalNative elem_type;
			gint32 num_elem; /* -1 if not set */
			gint16 param_num; /* -1 if not set */
			gint16 elem_mult; /* -1 if not set */
		} array_data;
		struct {
			char *custom_name;
			char *cookie;
		} custom_data;
		struct {
			MonoMarshalVariant elem_type;
			gint32 num_elem;
		} safearray_data;
	} data;
} ;

enum _MonoMarshalNative{
	MONO_NATIVE_BOOLEAN = 0x02, /* 4 bytes, 0 is false, != 0 is true */
	MONO_NATIVE_I1 = 0x03,
	MONO_NATIVE_U1 = 0x04,
	MONO_NATIVE_I2 = 0x05,
	MONO_NATIVE_U2 = 0x06,
	MONO_NATIVE_I4 = 0x07,
	MONO_NATIVE_U4 = 0x08,
	MONO_NATIVE_I8 = 0x09,
	MONO_NATIVE_U8 = 0x0a,
	MONO_NATIVE_R4 = 0x0b,
	MONO_NATIVE_R8 = 0x0c,
	MONO_NATIVE_CURRENCY = 0x0f,
	MONO_NATIVE_BSTR = 0x13, /* prefixed length, Unicode */
	MONO_NATIVE_LPSTR = 0x14, /* ANSI, null terminated */
	MONO_NATIVE_LPWSTR = 0x15, /* UNICODE, null terminated */
	MONO_NATIVE_LPTSTR = 0x16, /* plattform dep., null terminated */
	MONO_NATIVE_BYVALTSTR = 0x17,
	MONO_NATIVE_IUNKNOWN = 0x19,
	MONO_NATIVE_IDISPATCH = 0x1a,
	MONO_NATIVE_STRUCT = 0x1b,
	MONO_NATIVE_INTERFACE = 0x1c,
	MONO_NATIVE_SAFEARRAY = 0x1d,
	MONO_NATIVE_BYVALARRAY = 0x1e,
	MONO_NATIVE_INT = 0x1f,
	MONO_NATIVE_UINT = 0x20,
	MONO_NATIVE_VBBYREFSTR = 0x22,
	MONO_NATIVE_ANSIBSTR = 0x23,  /* prefixed length, ANSI */
	MONO_NATIVE_TBSTR = 0x24, /* prefixed length, plattform dep. */
	MONO_NATIVE_VARIANTBOOL = 0x25,
	MONO_NATIVE_FUNC = 0x26,
	MONO_NATIVE_ASANY = 0x28,
	MONO_NATIVE_LPARRAY = 0x2a,
	MONO_NATIVE_LPSTRUCT = 0x2b,
	MONO_NATIVE_CUSTOM = 0x2c,
	MONO_NATIVE_ERROR = 0x2d,
	MONO_NATIVE_MAX = 0x50 /* no info */
};

enum _MonoMarshalVariant{
	MONO_VARIANT_EMPTY = 0x00,
	MONO_VARIANT_NULL = 0x01,
	MONO_VARIANT_I2 = 0x02,
	MONO_VARIANT_I4 = 0x03,
	MONO_VARIANT_R4 = 0x04,
	MONO_VARIANT_R8 = 0x05,
	MONO_VARIANT_CY = 0x06,
	MONO_VARIANT_DATE = 0x07,
	MONO_VARIANT_BSTR = 0x08,
	MONO_VARIANT_DISPATCH = 0x09,
	MONO_VARIANT_ERROR = 0x0a,
	MONO_VARIANT_BOOL = 0x0b,
	MONO_VARIANT_VARIANT = 0x0c,
	MONO_VARIANT_UNKNOWN = 0x0d,
	MONO_VARIANT_DECIMAL = 0x0e,
	MONO_VARIANT_I1 = 0x10,
	MONO_VARIANT_UI1 = 0x11,
	MONO_VARIANT_UI2 = 0x12,
	MONO_VARIANT_UI4 = 0x13,
	MONO_VARIANT_I8 = 0x14,
	MONO_VARIANT_UI8 = 0x15,
	MONO_VARIANT_INT = 0x16,
	MONO_VARIANT_UINT = 0x17,
	MONO_VARIANT_VOID = 0x18,
	MONO_VARIANT_HRESULT = 0x19,
	MONO_VARIANT_PTR = 0x1a,
	MONO_VARIANT_SAFEARRAY = 0x1b,
	MONO_VARIANT_CARRAY = 0x1c,
	MONO_VARIANT_USERDEFINED = 0x1d,
	MONO_VARIANT_LPSTR = 0x1e,
	MONO_VARIANT_LPWSTR = 0x1f,
	MONO_VARIANT_RECORD = 0x24,
	MONO_VARIANT_FILETIME = 0x40,
	MONO_VARIANT_BLOB = 0x41,
	MONO_VARIANT_STREAM = 0x42,
	MONO_VARIANT_STORAGE = 0x43,
	MONO_VARIANT_STREAMED_OBJECT = 0x44,
	MONO_VARIANT_STORED_OBJECT = 0x45,
	MONO_VARIANT_BLOB_OBJECT = 0x46,
	MONO_VARIANT_CF = 0x47,
	MONO_VARIANT_CLSID = 0x48,
	MONO_VARIANT_VECTOR = 0x1000,
	MONO_VARIANT_ARRAY = 0x2000,
	MONO_VARIANT_BYREF = 0x4000
} ;

struct _MonoClassRuntimeInfo{
	guint16 max_domain;
	/* domain_vtables is indexed by the domain id and the size is max_domain + 1 */
	MonoVTable *domain_vtables[MONO_ZERO_LEN_ARRAY];
} ;

struct _MonoClassExt{
	struct {
		guint32 first, count;
	} property, event;

	/* Initialized by a call to mono_class_setup_properties () */
	MonoProperty *properties;

	/* Initialized by a call to mono_class_setup_events () */
	MonoEvent *events;

	guint32    declsec_flags;	/* declarative security attributes flags */

	/* Default values/RVA for fields */
	/* Accessed using mono_class_get_field_default_value () / mono_field_get_data () */
	MonoFieldDefaultValue *field_def_values;

	GList      *nested_classes;
} ;

struct _MonoProperty {
	MonoClass *parent;
	const char *name;
	MonoMethod *get;
	MonoMethod *set;
	guint32 attrs;
};

struct _MonoEvent {
	MonoClass *parent;
	const char *name;
	MonoMethod *add;
	MonoMethod *remove;
	MonoMethod *raise;
	MonoMethod **other;
	guint32 attrs;
};

struct _MonoFieldDefaultValue {
	/*
	* If the field is constant, pointer to the metadata constant
	* value.
	* If the field has an RVA flag, pointer to the data.
	* Else, invalid.
	*/
	const char      *data;

	/* If the field is constant, the type of the constant. */
	MonoTypeEnum     def_type;
} ;


struct _MonoString{
	MonoObject object;
	gint32 length;
	gunichar2 chars[MONO_ZERO_LEN_ARRAY];
};

struct _MonoArray{
	MonoObject obj;
	/* bounds is NULL for szarrays */
	MonoArrayBounds *bounds;
	/* total number of elements of the array */
	mono_array_size_t max_length;
	/* we use double to ensure proper alignment on platforms that need it */
	double vector[MONO_ZERO_LEN_ARRAY];
};

struct _MonoArrayBounds{
	mono_array_size_t length;
	mono_array_lower_bound_t lower_bound;
} ;


struct _MonoMarshalByRefObject{
	MonoObject obj;
	MonoObject *identity;
} ;

struct _MonoAppContext {
	MonoObject obj;
	gint32 domain_id;
	gint32 context_id;
	gpointer *static_data;
};

struct _MonoException {
	MonoObject object;
	/* Stores the IPs and the generic sharing infos
	(vtable/MRGCTX) of the frames. */
	MonoArray  *trace_ips;
	MonoObject *inner_ex;
	MonoString *message;
	MonoString *help_link;
	MonoString *class_name;
	MonoString *stack_trace;
	MonoString *remote_stack_trace;
	gint32	    remote_stack_index;
	gint32	    hresult;
	MonoString *source;
	MonoObject *_data;
};

struct _MonoGHashTable {
	GHashFunc      hash_func;
	GEqualFunc     key_equal_func;

	Slot **table;
	int   table_size;
	int   in_use;
	int   threshold;
	int   last_rehash;
	GDestroyNotify value_destroy_func, key_destroy_func;
	MonoGHashGCType gc_type;
};

enum _MonoGHashGCType{
	MONO_HASH_CONSERVATIVE_GC,
	MONO_HASH_KEY_GC,
	MONO_HASH_VALUE_GC,
	MONO_HASH_KEY_VALUE_GC /* note this is the OR of the other two values */
} ;

struct _MonoJitInfoTable
{
	MonoDomain	       *domain;
	int			num_chunks;
	MonoJitInfoTableChunk  *chunks[MONO_ZERO_LEN_ARRAY];
};

struct _MonoJitInfoTableChunk
{
	int		       refcount;
	volatile int           num_elements;
	volatile gint8        *last_code_end;
	MonoJitInfo * volatile data[MONO_JIT_INFO_TABLE_CHUNK_SIZE];
};


struct _MonoJitExceptionInfo{
	guint32  flags;
	gint32   exvar_offset;
	gpointer try_start;
	gpointer try_end;
	gpointer handler_start;
	union {
		MonoClass *catch_class;
		gpointer filter;
	} data;
} ;

enum _MonoImageOpenStatus{
	MONO_IMAGE_OK,
	MONO_IMAGE_ERROR_ERRNO,
	MONO_IMAGE_MISSING_ASSEMBLYREF,
	MONO_IMAGE_IMAGE_INVALID
};

enum _MonoSecurityMode{
	MONO_SECURITY_MODE_NONE,
	MONO_SECURITY_MODE_CORE_CLR,
	MONO_SECURITY_MODE_CAS,
	MONO_SECURITY_MODE_SMCS_HACK
};

struct _MonoAppDomain {
	MonoMarshalByRefObject mbr;
	MonoDomain *data;
};

struct _MonoType {
	union {
		MonoClass *klass; /* for VALUETYPE and CLASS */
		_MonoType *type;   /* for PTR */
		MonoArrayType *array; /* for ARRAY */
		MonoMethodSignature *method;
		MonoGenericParam *generic_param; /* for VAR and MVAR */
		MonoGenericClass *generic_class; /* for GENERICINST */
	} data;
	unsigned int attrs : 16; /* param attributes or field flags */
	MonoTypeEnum type : 8;
	unsigned int num_mods : 6;  /* max 64 modifiers follow at the end */
	unsigned int byref : 1;
	unsigned int pinned : 1;  /* valid when included in a local var signature */
	MonoCustomMod modifiers[MONO_ZERO_LEN_ARRAY]; /* this may grow */
};

struct _MonoClass {
	/* element class for arrays and enum basetype for enums */
	MonoClass *element_class;
	/* used for subtype checks */
	MonoClass *cast_class;

	/* for fast subtype checks */
	MonoClass **supertypes;
	guint16     idepth;

	/* array dimension */
	guint8     rank;

	int        instance_size; /* object instance size */

	USE_UINT8_BIT_FIELD(guint, inited          : 1);
	/* We use init_pending to detect cyclic calls to mono_class_init */
	USE_UINT8_BIT_FIELD(guint, init_pending    : 1);

	/* A class contains static and non static data. Static data can be
	* of the same type as the class itselfs, but it does not influence
	* the instance size of the class. To avoid cyclic calls to
	* mono_class_init (from mono_class_instance_size ()) we first
	* initialise all non static fields. After that we set size_inited
	* to 1, because we know the instance size now. After that we
	* initialise all static fields.
	*/
	USE_UINT8_BIT_FIELD(guint, size_inited     : 1);
	USE_UINT8_BIT_FIELD(guint, valuetype       : 1); /* derives from System.ValueType */
	USE_UINT8_BIT_FIELD(guint, enumtype        : 1); /* derives from System.Enum */
	USE_UINT8_BIT_FIELD(guint, blittable       : 1); /* class is blittable */
	USE_UINT8_BIT_FIELD(guint, unicode         : 1); /* class uses unicode char when marshalled */
	USE_UINT8_BIT_FIELD(guint, wastypebuilder  : 1); /* class was created at runtime from a TypeBuilder */
	/* next byte */
	guint8 min_align;
	/* next byte */
	USE_UINT8_BIT_FIELD(guint, packing_size    : 4);
	USE_UINT8_BIT_FIELD(guint, has_unity_native_intptr : 1); // This class has a IntPtr that points to a native class with an asset reference
	/* still 3 bits free */
	/* next byte */
	USE_UINT8_BIT_FIELD(guint, ghcimpl         : 1); /* class has its own GetHashCode impl */
	USE_UINT8_BIT_FIELD(guint, has_finalize    : 1); /* class has its own Finalize impl */
	USE_UINT8_BIT_FIELD(guint, marshalbyref    : 1); /* class is a MarshalByRefObject */
	USE_UINT8_BIT_FIELD(guint, contextbound    : 1); /* class is a ContextBoundObject */
	USE_UINT8_BIT_FIELD(guint, delegate        : 1); /* class is a Delegate */
	USE_UINT8_BIT_FIELD(guint, gc_descr_inited : 1); /* gc_descr is initialized */
	USE_UINT8_BIT_FIELD(guint, has_cctor       : 1); /* class has a cctor */
	USE_UINT8_BIT_FIELD(guint, has_references  : 1); /* it has GC-tracked references in the instance */
	/* next byte */
	USE_UINT8_BIT_FIELD(guint, has_static_refs : 1); /* it has static fields that are GC-tracked */
	USE_UINT8_BIT_FIELD(guint, no_special_static_fields : 1); /* has no thread/context static fields */
	/* directly or indirectly derives from ComImport attributed class.
	* this means we need to create a proxy for instances of this class
	* for COM Interop. set this flag on loading so all we need is a quick check
	* during object creation rather than having to traverse supertypes
	*/
	USE_UINT8_BIT_FIELD(guint, is_com_object   : 1);
	USE_UINT8_BIT_FIELD(guint, nested_classes_inited : 1); /* Whenever nested_class is initialized */
	USE_UINT8_BIT_FIELD(guint, interfaces_inited : 1); /* interfaces is initialized */
	USE_UINT8_BIT_FIELD(guint, simd_type       : 1); /* class is a simd intrinsic type */
	USE_UINT8_BIT_FIELD(guint, is_generic      : 1); /* class is a generic type definition */
	USE_UINT8_BIT_FIELD(guint, is_inflated     : 1); /* class is a generic instance */

	guint8     exception_type;	/* MONO_EXCEPTION_* */

	/* Additional information about the exception */
	/* Stored as property MONO_CLASS_PROP_EXCEPTION_DATA */
	//void       *exception_data;

	MonoClass  *parent;
	MonoClass  *nested_in;

	MonoImage *image;
	const char *name;
	const char *name_space;

	guint32    type_token;
	int        vtable_size; /* number of slots */

	guint16     interface_count;
	guint16     interface_id;        /* unique inderface id (for interfaces) */
	guint16     max_interface_id;

	guint16     interface_offsets_count;
	MonoClass **interfaces_packed;
	guint16    *interface_offsets_packed;
	guint8     *interface_bitmap;

	MonoClass **interfaces;

	union {
		int class_size; /* size of area for static fields */
		int element_size; /* for array types */
		int generic_param_token; /* for generic param types, both var and mvar */
	} sizes;

	/*
	* From the TypeDef table
	*/
	guint32    flags;
	struct {
		guint32 first, count;
	} field, method;

	/* loaded on demand */
	MonoMarshalType *marshal_info;

	/*
	* Field information: Type and location from object base
	*/
	MonoClassField *fields;

	MonoMethod **methods;

	/* used as the type of the this argument and when passing the arg by value */
	MonoType this_arg;
	MonoType byval_arg;

	MonoGenericClass *generic_class;
	MonoGenericContainer *generic_container;

	void *reflection_info;

	void *gc_descr;

	MonoClassRuntimeInfo *runtime_info;

	/* next element in the class_cache hash list (in MonoImage) */
	MonoClass *next_class_cache;

	/* Generic vtable. Initialized by a call to mono_class_setup_vtable () */
	MonoMethod **vtable;

	/* Rarely used fields of classes */
	MonoClassExt *ext;
};

struct _MonoGenericContainer {
	MonoGenericContext context;
	/* If we're a generic method definition in a generic type definition,
	the generic container of the containing class. */
	MonoGenericContainer *parent;
	/* the generic type definition or the generic method definition corresponding to this container */
	union {
		MonoClass *klass;
		MonoMethod *method;
	} owner;
	int type_argc : 31;
	/* If true, we're a generic method, otherwise a generic type definition. */
	/* Invariant: parent != NULL => is_method */
	int is_method : 1;
	/* Our type parameters. */
	MonoGenericParamFull *type_params;

	/*
	* For owner-less containers created by SRE, the image the container was
	* allocated from.
	*/
	MonoImage *image;
};

struct _MonoGenericParamFull{
	MonoGenericParam param;
	MonoGenericParamInfo info;
};

struct _MonoJitInfo {
	/* NOTE: These first two elements (method and
	next_jit_code_hash) must be in the same order and at the
	same offset as in RuntimeMethod, because of the jit_code_hash
	internal hash table in MonoDomain. */
	MonoMethod *method;
	struct _MonoJitInfo *next_jit_code_hash;
	gpointer    code_start;
	/* This might contain an id for the unwind info instead of a register mask */
	guint32     used_regs;
	int         code_size;
	guint32     num_clauses : 15;
	/* Whenever the code is domain neutral or 'shared' */
	gboolean    domain_neutral : 1;
	gboolean    cas_inited : 1;
	gboolean    cas_class_assert : 1;
	gboolean    cas_class_deny : 1;
	gboolean    cas_class_permitonly : 1;
	gboolean    cas_method_assert : 1;
	gboolean    cas_method_deny : 1;
	gboolean    cas_method_permitonly : 1;
	gboolean    has_generic_jit_info : 1;
	gboolean    from_aot : 1;
	gboolean    from_llvm : 1;
#ifdef HAVE_SGEN_GC
	/* FIXME: Embed this after the structure later */
	gpointer    gc_info;
#endif
	MonoJitExceptionInfo clauses[MONO_ZERO_LEN_ARRAY];
	/* There is an optional MonoGenericJitInfo after the clauses */
};




typedef MonoAssembly* (*mono_domain_assembly_open_t)(MonoDomain *domain, const char *name);
typedef MonoAssembly* (*mono_assembly_open_t)(const char *filename, MonoImageOpenStatus *status);
typedef int (*mono_jit_exec_t)(MonoDomain *domain, MonoAssembly *assembly, int argc, char *argv[]);
typedef MonoDomain* (*mono_domain_get_t)();
typedef MonoClass* (*mono_class_from_name_t)(MonoImage *image, const char* name_space, const char *name);
typedef gboolean (*mono_class_init_t)(MonoClass *pclass);
typedef MonoMethod* (*mono_class_get_method_from_name_t)(MonoClass *klass, const char *name, int param_count);
typedef MonoObject* (*mono_runtime_invoke_t)(MonoMethod *method, void *obj, void **params, MonoObject **exc);
typedef MonoObject* (*mono_object_new_t)(MonoDomain *domain, MonoClass *klass);
typedef void (*mono_runtime_object_init_t)(MonoObject *pthis);
typedef void (*mono_security_set_mode_t)(MonoSecurityMode mode);
typedef void (*mono_security_set_core_clr_platform_callback_t)(MonoCoreClrPlatformCB callback);


mono_domain_assembly_open_t mono_domain_assembly_open;
mono_assembly_open_t mono_assembly_open;
mono_jit_exec_t mono_jit_exec;
mono_domain_get_t mono_domain_get;
mono_class_from_name_t mono_class_from_name;
mono_class_init_t mono_class_init;
mono_class_get_method_from_name_t mono_class_get_method_from_name;
mono_runtime_invoke_t mono_runtime_invoke;
mono_object_new_t mono_object_new;
mono_runtime_object_init_t mono_runtime_object_init;
mono_security_set_mode_t mono_security_set_mode;
mono_security_set_core_clr_platform_callback_t mono_security_set_core_clr_platform_callback;
