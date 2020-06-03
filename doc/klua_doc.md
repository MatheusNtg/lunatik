# KLua API Documentation

KLua is the portion of Lunatik responsable for states management. One API is provided to user in order to access all operations provided by KLua. Some of those operations are:

* States creation
* States deletion
* States listing
* Lua code execution from a chosen state

The API is based in two main structures, they are `struct klua_state` and `struct meta_state`, the first one being responsable for datas related to Lunatik and the second one being the data structure to storage all `struct klua_state` inside the API, providing multiples, indepentend contexts in the API for the user's use.

## The `klua_state` struct

Defined at `states.h` as:

```c
struct klua_state
{
	struct hlist_node node;
	struct meta_state *ms;
	lua_State *L;
	spinlock_t lock;
	refcount_t users;
	size_t maxalloc;
	size_t curralloc;
	unsigned char name[KLUA_NAME_MAXSIZE];
}
```

The elements in the struct has the following meaning:

 **`struct hlist_node node`** 
Is a variable used by the kernel hash table api to storage the `struct klua_state`.

**`struct meta_state *ms`**
The meta-state which the instance of some `struct klua_state` belongs to.

**`lua_State L`** 
Is the Lua state used by lunatik to do all operations related to Lua.

**`spinlock_t lock`** 
Is a spinlock variable used to handle concurrency control.

**`refcount_t users`** 
Represents how many users are referring to a given state.

**`size_t maxalloc`** 
Represents the maximum memory that the lua state `L` can use.

**`size_t curralloc`** 
Represents the current memory that the lua state `L` is using.

**`unsigned char name[KLUA_NAME_MAXSIZE]`** 
Is the unique identifier to `klua_state`, used to search it in the kernel hash table, note that this is limited by `KLUA_NAME_MAXSIZE`.

## The `meta_state` struct

Defined at `states.h` as:
```c
struct meta_state
{
	struct hlist_head states_table[KLUA_MAX_STATES_COUNT];
	spinlock_t statestable_lock;
	spinlock_t rfcnt_lock;
	atomic_t states_count;
};
```
The elements in the struct has the following meaning:

**`struct hlist_head states_table[KLUA_MAX_STATES_COUNT]`**
Table used to store all `struct klua_state` present in some meta-state.

**`spinlock_t statestable_lock`**
A spinlock variable used to handle concurrency control in the `states_table` operations.

**`spinlock_t rfcnt_lock`**
A spinlock variable used to handle concurrency control in the operations of `users`'s attribute of `klua_state`.

**`atomic_t states_count`**
A counter to the numbers of states present in a instance of `struct meta_state`


## Functions offered by the API

**`struct meta_state *klua_states_init(void)`**
Initializes the API. You have to call this function before use any of the operations offered by this API, when all operations is done you have to call `klua_states_exit()`. It returns a `struct meta_state` to work on.

**`struct klua_state *klua_state_lookup(struct meta_state *ms, const char *name);`**
Searches for a `struct klua_state` in the meta-state `ms` with the name `name`. Returns a pointer to the `struct klua_state` case a state with that name is found or `NULL` otherwise.

**`struct klua_state *klua_state_create(struct meta_state *ms, size_t maxalloc, const char *name)`**
Creates in the meta-state `ms` a lunatik state with the max memory usage defined by `maxalloc` and a unique identifier to acess such state defined by `name`. Return a pointer to `struct klua_state` represeting the lunatik or `NULL` if any errors occours during the creation.

**`int klua_state_destroy(struct meta_state *ms, const char *name)`**
Searches for a lunatik state represented by the name `name` in the meta-state `ms` , case such state is found deletes it. Returns `0` case the deletion occours and `-1` ortherwise.

**`void klua_state_list(struct meta_state *ms)`**
List on dmesg all states present in the meta-state `ms` and their properties.

**`void klua_state_destroy_all(struct meta_state *ms)`**
Destroy all states of the meta-state `ms`.

**`void klua_execute(struct meta_state *ms, const char *name, const char *code)`**
Searches for the state represented by `name` inside of the meta-state `ms` and executes the code `code` on Lunatik.
