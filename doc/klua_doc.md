# KLua API Documentation

The whole API is based on the structure `klua_state`, which represents a lunatik state. You can do all operations related to states management from that structure. The operations offered by the API are:

* States creation
* States deletion
* Code execution from a given `klua_state`
* State lookup

## The `klua_state` struct

Defined at `states.h` as:

```c
struct klua_state
{
	struct hlist_node node;
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


## Functions offered by the API

`void klua_states_init()`
Initializes the API. You have to call this function before use any of the operations offered by this API, when all operations is done you have to call `klua_states_exit()`.

`struct klua_state *klua_state_lookup(const char *name)`
Searches for a `struct klua_state` with the identifier `name` passed as argument to the function. Returns a pointer to the `struct klua_state` case a state with that name is found or `NULL` otherwise.

`struct klua_state *klua_state_create(size_t maxalloc, const char *name)`
Creates a lunatik state with the max memory usage defined by `maxalloc` and a unique identifier to acess such state defined by `name`. Return a pointer to `struct klua_state` represeting the lunatik or `NULL` if any errors occours during the creation.

`int klua_state_destroy(const char *name)`
Searches for a lunatik state represented by the name `name` and case such state is found deletes it. Returns `0` case the deletion is occours and `-1` ortherwise.

`void klua_state_list()`
List on dmesg all created states and their properties.

`void klua_state_destroy_all()`
Destroy all created states.

`void klua_execute(const char *name, const char *code)`
Searches for the state represented by `name` and executes the code `code` on lunatik.

