# udebug - OpenWrt debugging infrastructure

udebug assists whole-system debugging by making it easy to provide ring buffers
with debug data and make them accessible through a unified API.
Through the CLI, you can either create snapshots of data with a specific duration,
or stream data in real time. The data itself is stored in .pcapng files, which can
contain a mix of packets and log messages.

## libudebug C API

#### `void udebug_init(struct udebug *ctx)`

Initializes the udebug context. Must be called before adding buffers.

#### `int udebug_connect(struct udebug *ctx, const char *path)`

Connect to udebugd and submit any buffers that were added using `udebug_buf_add`.

#### `void udebug_auto_connect(struct udebug *ctx, const char *path)`

Connects and automatically reconnects to udebugd. Uses uloop and calls `udebug_add_uloop`.

#### `void udebug_free(struct udebug *ctx)`

Frees the udebug context and all added created buffers.

#### `int udebug_buf_init(struct udebug_buf *buf, size_t entries, size_t size)`

Allocates a buffer with a given size. Entries and size are rounded up internally to the
nearest power-of-2.

#### `int udebug_buf_add(struct udebug *ctx, struct udebug_buf *buf, const struct udebug_buf_meta *meta);`

Submits the buffer to udebugd and makes it visible.

#### `void udebug_buf_free(struct udebug_buf *buf)`

Removes the buffer from udebugd and frees it.

#### `void udebug_entry_init(struct udebug_buf *buf)`

Initializes a new entry on the ring buffer.

#### `void *udebug_entry_append(struct udebug_buf *buf, const void *data, uint32_t len)`

Appends data to the ring buffer. When called with data == NULL, space is only
reserved, and the return value provides a pointer with len bytes that can be
written to.

#### `int udebug_entry_printf(struct udebug_buf *buf, const char *fmt, ...)`

Appends a string to the buffer, based on format string + arguments (like printf)

#### `int udebug_entry_vprintf(struct udebug_buf *buf, const char *fmt, va_list ap)`

Like `udebug_entry_printf()`

#### `void udebug_entry_add(struct udebug_buf *buf)`

Finalizes and publishes the entry on the ring buffer.

### Simple example

```
static struct udebug ud;
static struct udebug_buf udb;

/* ... */

uloop_init();
udebug_init(&ud);
udebug_auto_connect(&ud, NULL);

static const struct udebug_buf_meta buf_meta = {
	.name = "counter",
	.format = UDEBUG_FORMAT_STRING,
};

int entries = 128;
int data_size = 1024;

udebug_buf_init(&udb, entries, data_size);
udebug_buf_add(&ud, &udb, &buf_meta);

/* ... */

udebug_entry_init(&udb); // initialize entry
udebug_entry_printf(&udb, "count=%d", count++);
udebug_entry_add(&udb); // finalize the entry

```

## udebug CLI

```
Usage: udebug-cli [<options>] <command> [<args>]

  Options:
    -f                          Ignore errors on opening rings
    -d <duration>:              Only fetch data up to <duration> seconds old
    -o <file>|-                 Set output file for snapshot/stream (or '-' for stdout)
    -i <process>[:<name>]       Select debug buffer for snapshot/stream
    -s <path>                   Use udebug socket <path>
    -q                          Suppress warnings/error messages

  Commands:
    list:                       List available debug buffers
    snapshot:                   Create a pcapng snapshot of debug buffers
    set_flag [<name>=0|1 ...]   Set ring buffer flags
    get_flags                   Get ring buffer flags

```

