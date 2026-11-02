// single thread right now.
#include "infinistore.h"

#include <arpa/inet.h>
#include <assert.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <future>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include <boost/lockfree/spsc_queue.hpp>
#include <boost/smart_ptr/intrusive_ptr.hpp>

#include "ibv_helper.h"
#include "protocol.h"
#include "rdma.h"

server_config_t global_config;

uv_loop_t *loop;
uv_tcp_t server;

MM *mm;

struct rdma_device rdma_dev;

// indicate if the MM extend is in flight
bool extend_in_flight = false;

// evict memory from head to tail, the PTR is shared by lru_queue and kv_map
// so we have to pop from both to evict the memory
std::list<boost::intrusive_ptr<PTR>> lru_queue;
std::unordered_map<std::string, boost::intrusive_ptr<PTR>> kv_map;

typedef enum {
    READ_HEADER,
    READ_BODY,
    READ_VALUE_THROUGH_TCP,
} read_state_t;

// the max data could be send in uv_write
static const size_t MAX_SEND_SIZE = 256 << 10;

const float ON_DEMAND_MIN_THRESHOLD = 0.8;
const float ON_DEMAND_MAX_THRESHOLD = 0.95;

struct Client;
typedef struct Client client_t;

struct kv_msg_t {
    enum kind_t { RECV_REQ, SYNC } kind;
    client_t *client = nullptr;
    virtual ~kv_msg_t() = default;
};

struct recv_task_t : kv_msg_t {
    int buf_idx = -1;
    char op = 0;
    int block_size = 0;
    uint32_t rkey = 0;
    std::vector<std::string> keys;
    std::vector<uint64_t> remote_addrs;
    recv_task_t() { kind = RECV_REQ; }
};

struct kv_sync_task_t : kv_msg_t {
    std::function<void()> fn;
    std::promise<void> done;
    kv_sync_task_t() { kind = SYNC; }
};

struct rdma_done_t {
    client_t *client = nullptr;
    uint64_t wr_id = 0;
    enum ibv_wc_opcode opcode = IBV_WC_RDMA_READ;
    enum ibv_wc_status status = IBV_WC_SUCCESS;
};

struct rdma_submit_t {
    client_t *client = nullptr;
    enum ibv_wr_opcode opcode = IBV_WR_RDMA_READ;
    uint32_t rkey = 0;
    std::vector<boost::intrusive_ptr<PTR>> *ops = nullptr;
    std::vector<uint64_t> remote_addrs;
    size_t offset = 0;
};

struct ack_task_t {
    client_t *client = nullptr;
    int return_code = 0;
};

static boost::lockfree::spsc_queue<kv_msg_t *, boost::lockfree::capacity<8192>> _recv_task_q;
static boost::lockfree::spsc_queue<rdma_done_t *, boost::lockfree::capacity<8192>> _rdma_done_q;
static boost::lockfree::spsc_queue<rdma_submit_t *, boost::lockfree::capacity<8192>> _rdma_submit_q;
static boost::lockfree::spsc_queue<ack_task_t *, boost::lockfree::capacity<8192>> _ack_q;

static std::thread _kv_thread;
static std::thread _sq_thread;
static std::atomic<bool> _pipeline_stop{false};
static std::atomic<bool> _kv_running{false};
static std::thread::id _kv_thread_id;
static std::mutex _kv_mu;
static std::condition_variable _kv_cv;
static std::mutex _sq_mu;
static std::condition_variable _sq_cv;

static void kv_poller_loop();
static void sq_submit_poller_loop();
static void evict_cache_locked(float min_threshold, float max_threshold);

static void run_in_kv_thread(std::function<void()> fn) {
    if (!_kv_running.load() || std::this_thread::get_id() == _kv_thread_id) {
        fn();
        return;
    }

    kv_sync_task_t *task = new kv_sync_task_t();
    task->fn = std::move(fn);
    std::future<void> done = task->done.get_future();

    while (!_recv_task_q.push(task)) {
        std::this_thread::yield();
    }
    _kv_cv.notify_one();

    if (done.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
        ERROR("kv_poller did not finish the sync task in time");
    }
    delete task;
}

struct Client {
    uv_tcp_t *handle_ = NULL;    // uv_stream_t
    read_state_t state_;         // state of the client, for parsing the request
    size_t bytes_read_ = 0;      // bytes read so far, for parsing the request
    size_t expected_bytes_ = 0;  // expected size of the body
    header_t header_;

    boost::intrusive_ptr<PTR> current_tcp_task_;

    // RDMA recv buffer
    char *recv_buffer_[MAX_RECV_WR] = {};
    struct ibv_mr *recv_mr_[MAX_RECV_WR] = {};

    // RDMA send buffer
    char *send_buffer_ = NULL;
    struct ibv_mr *send_mr_ = NULL;
    std::atomic<int> outstanding_rdma_ops_{0};

    std::atomic<int> refs_{1};
    std::atomic<bool> closing_{false};

    // TCP send buffer
    char *tcp_send_buffer_ = NULL;
    char *tcp_recv_buffer_ = NULL;

    rdma_conn_info_t remote_info_;
    rdma_conn_info_t local_info_;

    bool rdma_connected_ = false;

    rdma_context rdma_ctx_;

    uv_poll_t poll_handle_;

    Client() = default;
    Client(const Client &) = delete;
    ~Client();

    void cq_poll_handle(uv_poll_t *handle, int status, int events);
    void drain_cq();
    int read_rdma_cache(recv_task_t *task);
    int write_rdma_cache(recv_task_t *task);
    void post_ack(int return_code);
    void post_ack_immediate(int return_code);
    int allocate_rdma(const RemoteMetaRequest *req);
    // send response to client through TCP
    void send_resp(int return_code, void *buf, size_t size);
    int tcp_payload_request(const TCPPayloadRequest *request);
    int sync_stream();
    void reset_client_read_state();
    int check_key(const std::string &key_to_check);
    int get_match_last_index(const GetMatchLastIndexRequest *request);
    int delete_keys(const DeleteKeysRequest *request);
    int rdma_exchange();
    int prepare_recv_rdma_request(int buf_idx);
    int perform_batch_rdma(rdma_submit_t *submit);
    void handle_rdma_done(rdma_done_t *done);
};

typedef struct Client client_t;

static void client_retain(client_t *client) { client->refs_.fetch_add(1); }

static void client_release(client_t *client) {
    if (client->refs_.fetch_sub(1) == 1) {
        delete client;
    }
}

Client::~Client() {
    INFO("free client resources");

    if (handle_) {
        free(handle_);
        handle_ = NULL;
    }

    if (send_mr_) {
        ibv_dereg_mr(send_mr_);
        send_mr_ = NULL;
    }

    if (send_buffer_) {
        free(send_buffer_);
        send_buffer_ = NULL;
    }

    for (int i = 0; i < MAX_RECV_WR; i++) {
        if (recv_mr_[i]) {
            assert(recv_buffer_[i] != NULL);
            ibv_dereg_mr(recv_mr_[i]);
            recv_mr_[i] = NULL;
        }

        if (recv_buffer_[i]) {
            free(recv_buffer_[i]);
            recv_buffer_[i] = NULL;
        }
    }

    if (tcp_send_buffer_) {
        free(tcp_send_buffer_);
        tcp_send_buffer_ = NULL;
    }

    if (tcp_recv_buffer_) {
        free(tcp_recv_buffer_);
        tcp_recv_buffer_ = NULL;
    }

    destroy_rdma_context(&rdma_ctx_);
}

void on_close(uv_handle_t *handle) {
    client_t *client = (client_t *)handle->data;
    if (client == nullptr) {
        return;
    }
    handle->data = nullptr;

    client->drain_cq();
    client->closing_ = true;

    if (client->poll_handle_.data) {
        uv_poll_stop(&client->poll_handle_);
        client->poll_handle_.data = nullptr;
    }

    client_release(client);
}

struct BulkWriteCtx {
    client_t *client;
    uint32_t *header_buf;
    boost::intrusive_ptr<PTR> ptr;
    size_t offset;
    size_t total_size;
};

void on_chunk_write(uv_write_t *req, int status) {
    BulkWriteCtx *ctx = (BulkWriteCtx *)req->data;
    if (status < 0) {
        ERROR("Write error {}", uv_strerror(status));
        uv_close((uv_handle_t *)req->handle, on_close);
        free(req);
        delete ctx;
        return;
    }

    if (ctx->offset == ctx->total_size) {
        DEBUG("write done");
        ctx->client->reset_client_read_state();
        free(req);
        delete ctx;
        return;
    }
    size_t remain = ctx->total_size - ctx->offset;
    size_t send_size = MIN(remain, MAX_SEND_SIZE);
    uv_buf_t buf = uv_buf_init((char *)ctx->ptr->ptr + ctx->offset, send_size);
    ctx->offset += send_size;
    uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));
    write_req->data = ctx;
    uv_write(write_req, (uv_stream_t *)ctx->client->handle_, &buf, 1, on_chunk_write);
    free(req);
}

void on_head_write(uv_write_t *req, int status) {
    BulkWriteCtx *ctx = (BulkWriteCtx *)req->data;
    if (status < 0) {
        ERROR("Write error {}", uv_strerror(status));
        free(ctx->header_buf);
        delete ctx;
        uv_close((uv_handle_t *)req->handle, on_close);
        free(req);
        return;
    }

    DEBUG("header write done");
    size_t remain = ctx->total_size;
    size_t send_size = MIN(remain, MAX_SEND_SIZE);
    uv_buf_t buf = uv_buf_init((char *)ctx->ptr->ptr, send_size);
    ctx->offset += send_size;
    uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));
    write_req->data = ctx;
    uv_write(write_req, (uv_stream_t *)ctx->client->handle_, &buf, 1, on_chunk_write);
    free(req);
}

static void evict_cache_locked(float min_threshold, float max_threshold) {
    if (mm->usage() >= max_threshold) {
        // stop when mm->usage is below min_threshold
        float usage = mm->usage();
        while (mm->usage() >= min_threshold && !lru_queue.empty()) {
            auto ptr = lru_queue.front();
            lru_queue.pop_front();
            kv_map.erase(ptr->key);
        }
        INFO("evict memory done, usage: from {:.2f} => {:.2f}", usage, mm->usage());
    }
}

void evict_cache(float min_threshold, float max_threshold) {
    if (mm == nullptr) {
        return;
    }
    run_in_kv_thread([min_threshold, max_threshold]() {
        evict_cache_locked(min_threshold, max_threshold);
    });
}

void purge_kv_map() {
    run_in_kv_thread([]() {
        kv_map.clear();
        lru_queue.clear();
    });
}

size_t get_kvmap_len() {
    size_t len = 0;
    run_in_kv_thread([&len]() { len = kv_map.size(); });
    return len;
}

int Client::tcp_payload_request(const TCPPayloadRequest *req) {
    DEBUG("do tcp_payload_request... {}", op_name(req->op()));

    switch (req->op()) {
        case OP_TCP_PUT: {
            boost::intrusive_ptr<PTR> allocated_ptr;
            int ret = 0;

            run_in_kv_thread([&]() {
                evict_cache_locked(ON_DEMAND_MIN_THRESHOLD, ON_DEMAND_MAX_THRESHOLD);

                bool allocated = mm->allocate(
                    req->value_length(), 1,
                    [&](void *addr, uint32_t lkey, uint32_t rkey, int pool_idx) {
                        allocated_ptr = boost::intrusive_ptr<PTR>(
                            new PTR(addr, req->value_length(), pool_idx, req->key()->str()));
                    });
                if (!allocated) {
                    ret = OUT_OF_MEMORY;
                }
            });

            if (ret != 0) {
                ERROR("Failed to allocate memory");
                return ret;
            }

            DEBUG("allocated memory: addr: {}, lkey: {}, rkey: {}", allocated_ptr->ptr,
                  mm->get_lkey(allocated_ptr->pool_idx), mm->get_rkey(allocated_ptr->pool_idx));

            current_tcp_task_ = allocated_ptr;
            // set state machine
            state_ = READ_VALUE_THROUGH_TCP;
            bytes_read_ = 0;
            expected_bytes_ = req->value_length();
            break;
        }
        case OP_TCP_GET: {
            boost::intrusive_ptr<PTR> ptr;
            bool found = false;

            run_in_kv_thread([&]() {
                auto it = kv_map.find(req->key()->str());
                if (it == kv_map.end()) {
                    return;
                }
                found = true;
                ptr = it->second;

                // move ptr to the end of lru_queue
                lru_queue.erase(ptr->lru_it);
                lru_queue.push_back(ptr);
                ptr->lru_it = --lru_queue.end();
            });

            if (!found) {
                return KEY_NOT_FOUND;
            }

            uint32_t *header_buf = (uint32_t *)malloc(sizeof(uint32_t) * 2);
            header_buf[0] = FINISH;
            header_buf[1] = static_cast<uint32_t>(ptr->size);

            uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));

            // safe PTR to prevent it from being deleted early.
            write_req->data = new BulkWriteCtx{.client = this,
                                               .header_buf = header_buf,
                                               .ptr = ptr,
                                               .offset = 0,
                                               .total_size = ptr->size};

            uv_buf_t buf = uv_buf_init((char *)header_buf, sizeof(uint32_t) * 2);

            uv_write(write_req, (uv_stream_t *)handle_, &buf, 1, on_head_write);

            break;
        }
    }
    return 0;
}

void Client::post_ack(int return_code) {
    if (closing_.load()) {
        return;
    }
    ack_task_t *task = new ack_task_t();
    task->client = this;
    task->return_code = return_code;
    client_retain(this);
    while (!_ack_q.push(task)) {
        std::this_thread::yield();
    }
    _sq_cv.notify_one();
}

void Client::post_ack_immediate(int return_code) {
    // send an error code back
    struct ibv_send_wr wr = {0};
    struct ibv_send_wr *bad_wr = NULL;
    wr.wr_id = 0;
    wr.opcode = IBV_WR_SEND_WITH_IMM;
    wr.imm_data = return_code;
    wr.send_flags = 0;
    wr.sg_list = NULL;
    wr.num_sge = 0;
    wr.next = NULL;
    int ret = ibv_post_send(rdma_ctx_.qp, &wr, &bad_wr);
    if (ret) {
        ERROR("Failed to send WITH_IMM message: {}", strerror(ret));
    }
}

void Client::cq_poll_handle(uv_poll_t *handle, int status, int events) {
    // TODO: handle completion
    if (status < 0) {
        ERROR("Poll error: {}", uv_strerror(status));
        return;
    }
    struct ibv_cq *cq;
    void *cq_context;

    if (ibv_get_cq_event(rdma_ctx_.comp_channel, &cq, &cq_context) != 0) {
        ERROR("Failed to get CQ event");
        return;
    }
    ibv_ack_cq_events(cq, 1);

    if (ibv_req_notify_cq(cq, 0) != 0) {
        ERROR("Failed to request CQ notification");
        return;
    }

    struct ibv_wc wc = {0};
    while (ibv_poll_cq(cq, 1, &wc) > 0) {
        if (wc.status != IBV_WC_SUCCESS) {
            ERROR("CQ error: {}, {}", ibv_wc_status_str(wc.status), (unsigned long)wc.wr_id);
            if (wc.opcode == IBV_WC_RDMA_READ || wc.opcode == IBV_WC_RDMA_WRITE) {
                outstanding_rdma_ops_.fetch_sub(MAX_WR_BATCH);
                _sq_cv.notify_one();

                rdma_done_t *done = new rdma_done_t();
                done->client = this;
                done->wr_id = wc.wr_id;
                done->opcode = wc.opcode;
                done->status = wc.status;
                client_retain(this);
                while (!_rdma_done_q.push(done)) {
                    std::this_thread::yield();
                }
                _kv_cv.notify_one();
            }
            continue;
        }

        if (wc.opcode == IBV_WC_RECV) {  // recv RDMA read/write request
            const RemoteMetaRequest *request = GetRemoteMetaRequest(recv_buffer_[wc.wr_id]);

            DEBUG("Received remote meta request OP {}", op_name(request->op()));

            recv_task_t *task = new recv_task_t();
            task->client = this;
            task->buf_idx = (int)wc.wr_id;
            task->op = request->op();
            task->block_size = request->block_size();
            task->rkey = request->rkey();
            task->keys.reserve(request->keys()->size());
            for (const auto *key : *request->keys()) {
                task->keys.emplace_back(key->str());
            }
            task->remote_addrs.reserve(request->remote_addrs()->size());
            for (uint32_t i = 0; i < request->remote_addrs()->size(); i++) {
                task->remote_addrs.push_back(request->remote_addrs()->Get(i));
            }

            client_retain(this);
            while (!_recv_task_q.push(task)) {
                std::this_thread::yield();
            }
            _kv_cv.notify_one();

            if (prepare_recv_rdma_request(wc.wr_id) < 0) {
                ERROR("Failed to prepare recv rdma request");
                return;
            }
        }
        else if (wc.opcode == IBV_WC_SEND) {  // allocate: response sent
            DEBUG("allocate response sent");
        }
        else if (wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
            // client should not use WRITE_WITH_IMM to notify.
            // it should use COMMIT message to notify.
            WARN("WRITE_WITH_IMM is not supported in server side");
            if (prepare_recv_rdma_request(wc.wr_id) < 0) {
                ERROR("Failed to prepare recv rdma request");
                return;
            }
        }
        else if (wc.opcode == IBV_WC_RDMA_WRITE || wc.opcode == IBV_WC_RDMA_READ) {
            // some RDMA write(read cache WRs) is finished
            outstanding_rdma_ops_.fetch_sub(MAX_WR_BATCH);
            _sq_cv.notify_one();

            rdma_done_t *done = new rdma_done_t();
            done->client = this;
            done->wr_id = wc.wr_id;
            done->opcode = wc.opcode;
            done->status = wc.status;
            client_retain(this);
            while (!_rdma_done_q.push(done)) {
                std::this_thread::yield();
            }
            _kv_cv.notify_one();
        }
        else {
            ERROR("Unexpected wc opcode: {}", (int)wc.opcode);
        }
    }
}

void Client::drain_cq() {
    if (rdma_ctx_.cq == nullptr) {
        return;
    }
    struct ibv_wc wc = {0};
    while (ibv_poll_cq(rdma_ctx_.cq, 1, &wc) > 0) {
        if (wc.opcode != IBV_WC_RDMA_READ && wc.opcode != IBV_WC_RDMA_WRITE) {
            continue;
        }
        outstanding_rdma_ops_.fetch_sub(MAX_WR_BATCH);

        rdma_done_t *done = new rdma_done_t();
        done->client = this;
        done->wr_id = wc.wr_id;
        done->opcode = wc.opcode;
        done->status = wc.status;
        client_retain(this);
        while (!_rdma_done_q.push(done)) {
            std::this_thread::yield();
        }
        _kv_cv.notify_one();
    }
}

void extend_mempool() {
    if (global_config.auto_increase && mm->need_extend && !extend_in_flight) {
        INFO("Extend another mempool");
        extend_in_flight = true;
        run_in_kv_thread([]() { mm->add_mempool(rdma_dev.pd); });
        mm->need_extend = false;
        extend_in_flight = false;
    }
}

int Client::prepare_recv_rdma_request(int buf_idx) {
    struct ibv_sge sge = {0};
    struct ibv_recv_wr rwr = {0};
    struct ibv_recv_wr *bad_wr = NULL;
    sge.addr = (uintptr_t)(recv_buffer_[buf_idx]);
    sge.length = PROTOCOL_BUFFER_SIZE;
    sge.lkey = recv_mr_[buf_idx]->lkey;

    rwr.wr_id = buf_idx;
    rwr.next = NULL;
    rwr.sg_list = &sge;
    rwr.num_sge = 1;
    if (ibv_post_recv(rdma_ctx_.qp, &rwr, &bad_wr)) {
        ERROR("Failed to post receive, {}");
        return -1;
    }
    return 0;
}

int Client::perform_batch_rdma(rdma_submit_t *submit) {
    assert(submit->opcode == IBV_WR_RDMA_READ || submit->opcode == IBV_WR_RDMA_WRITE);

    const size_t total = submit->ops->size();
    if (submit->offset >= total) {
        return 0;
    }

    const size_t remain = total - submit->offset;
    const size_t batch = std::min(remain, (size_t)MAX_WR_BATCH);
    const bool last_batch = (submit->offset + batch == total);

    // check if next iteration will exceed the limit
    if (outstanding_rdma_ops_.load() + (int)MAX_WR_BATCH > MAX_RDMA_OPS_WR) {
        // if WR queue is full, we need to put them into queue
        return 0;
    }

    struct ibv_send_wr wrs[MAX_WR_BATCH] = {};
    struct ibv_sge sges[MAX_WR_BATCH] = {};

    for (size_t i = 0; i < batch; i++) {
        const auto &ptr = (*submit->ops)[submit->offset + i];

        sges[i].addr = (uintptr_t)ptr->ptr;
        sges[i].length = ptr->size;
        sges[i].lkey = mm->get_lkey(ptr->pool_idx);

        wrs[i].wr_id = 0;
        wrs[i].opcode = submit->opcode;
        wrs[i].sg_list = &sges[i];
        wrs[i].num_sge = 1;
        wrs[i].wr.rdma.remote_addr = submit->remote_addrs[submit->offset + i];
        wrs[i].wr.rdma.rkey = submit->rkey;
        wrs[i].next = (i + 1 == batch) ? nullptr : &wrs[i + 1];
        wrs[i].send_flags = (i + 1 == batch) ? IBV_SEND_SIGNALED : 0;
    }

    if (last_batch) {
        wrs[batch - 1].wr_id = (uintptr_t)submit->ops;
    }

    struct ibv_send_wr *bad_wr = nullptr;
    int ret = ibv_post_send(rdma_ctx_.qp, &wrs[0], &bad_wr);
    if (ret) {
        ERROR("Failed to post RDMA {}: {}",
              submit->opcode == IBV_WR_RDMA_READ ? "read" : "write", strerror(ret));
        return -1;
    }

    outstanding_rdma_ops_.fetch_add(MAX_WR_BATCH);
    submit->offset += batch;
    return (int)batch;
}

int Client::write_rdma_cache(recv_task_t *task) {
    DEBUG("do rdma write... num of keys: {}", task->keys.size());

    if (task->keys.size() != task->remote_addrs.size()) {
        ERROR("keys size and remote_addrs size mismatch");
        return INVALID_REQ;
    }

    // allocate memory
    int block_size = task->block_size;
    int n = task->keys.size();

    // create something.
    auto *inflight_rdma_writes = new std::vector<boost::intrusive_ptr<PTR>>;
    inflight_rdma_writes->reserve(n);

    evict_cache_locked(ON_DEMAND_MIN_THRESHOLD, ON_DEMAND_MAX_THRESHOLD);

    int key_idx = 0;
    bool allocated =
        mm->allocate(block_size, n, [&](void *addr, uint32_t lkey, uint32_t rkey, int pool_idx) {
            const auto &key = task->keys[key_idx];
            auto ptr = boost::intrusive_ptr<PTR>(new PTR(addr, block_size, pool_idx, key));
            DEBUG("writing key: {}", key);
            inflight_rdma_writes->push_back(ptr);
            key_idx++;
        });

    if (!allocated) {
        ERROR("Failed to allocate memory");
        delete inflight_rdma_writes;
        return OUT_OF_MEMORY;
    }

    // perform rdma read to receive data from client
    // read remote address data to local address
    auto *submit = new rdma_submit_t();
    submit->client = this;
    submit->opcode = IBV_WR_RDMA_READ;
    submit->rkey = task->rkey;
    submit->ops = inflight_rdma_writes;
    submit->remote_addrs = task->remote_addrs;

    client_retain(this);
    while (!_rdma_submit_q.push(submit)) {
        std::this_thread::yield();
    }
    _sq_cv.notify_one();

    return 0;
}

int Client::read_rdma_cache(recv_task_t *task) {
    DEBUG("do rdma read... num of keys: {}", task->keys.size());

    if (task->keys.size() != task->remote_addrs.size()) {
        ERROR("keys size and remote_addrs size mismatch");
        return INVALID_REQ;
    }

    auto *inflight_rdma_reads = new std::vector<boost::intrusive_ptr<PTR>>;
    inflight_rdma_reads->reserve(task->keys.size());

    for (const auto &key : task->keys) {
        auto it = kv_map.find(key);
        if (it == kv_map.end()) {
            WARN("Key not found: {}", key);
            delete inflight_rdma_reads;
            return KEY_NOT_FOUND;
        }
        const auto &ptr = it->second;

        if (ptr->size > (size_t)task->block_size) {
            WARN("remote region does not enough size: key:{}, actual size: {}, remote size :{}",
                 key, ptr->size, task->block_size);
            delete inflight_rdma_reads;
            return INVALID_REQ;
        }

        inflight_rdma_reads->push_back(ptr);
    }

    // loop over inflight_rdma_reads to update lru_queue
    for (auto &ptr : *inflight_rdma_reads) {
        lru_queue.erase(ptr->lru_it);
        lru_queue.push_back(ptr);
        ptr->lru_it = --lru_queue.end();
    }

    // write to remote address data from local address
    auto *submit = new rdma_submit_t();
    submit->client = this;
    submit->opcode = IBV_WR_RDMA_WRITE;
    submit->rkey = task->rkey;
    submit->ops = inflight_rdma_reads;
    submit->remote_addrs = task->remote_addrs;

    client_retain(this);
    while (!_rdma_submit_q.push(submit)) {
        std::this_thread::yield();
    }
    _sq_cv.notify_one();

    return 0;
}

void Client::handle_rdma_done(rdma_done_t *done) {
    if (done->status != IBV_WC_SUCCESS) {
        ERROR("RDMA operation failed: {}, wr_id: {}", ibv_wc_status_str(done->status),
              (unsigned long)done->wr_id);
        if (done->wr_id > 0) {
            auto *ops = (std::vector<boost::intrusive_ptr<PTR>> *)done->wr_id;
            delete ops;
            post_ack(INTERNAL_ERROR);
        }
        return;
    }

    // last WR will inform that all RDMA write is finished,so we can dereference PTR
    if (done->wr_id == 0) {
        return;
    }

    auto *ops = (std::vector<boost::intrusive_ptr<PTR>> *)done->wr_id;

    if (done->opcode == IBV_WC_RDMA_READ) {
        for (auto &ptr : *ops) {
            kv_map[ptr->key] = ptr;
            DEBUG("writing key done, {}", ptr->key);
            lru_queue.push_back(ptr);
            ptr->lru_it = --lru_queue.end();
        }
        delete ops;
        post_ack(FINISH);
    }
    else if (done->opcode == IBV_WC_RDMA_WRITE) {
        delete ops;
        post_ack(FINISH);
    }
}

// FIXME:
void Client::reset_client_read_state() {
    state_ = READ_HEADER;
    bytes_read_ = 0;
    expected_bytes_ = FIXED_HEADER_SIZE;
    memset(&header_, 0, sizeof(header_t));
    // keep the tcp_recv_buffer/tcp_send_buffer as it is
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

int verify_header(header_t *header) {
    if (header->magic != MAGIC) {
        return INVALID_REQ;
    }
    // TODO: add more checks
    return 0;
}

void on_write(uv_write_t *req, int status) {
    if (status < 0) {
        ERROR("Write error {}", uv_strerror(status));
        uv_close((uv_handle_t *)req->handle, on_close);
    }
    free(req);
}

int Client::rdma_exchange() {
    INFO("do rdma exchange...");

    int ret;

    if (rdma_connected_ == true) {
        ERROR("RDMA already connected");
        return SYSTEM_ERROR;
    }

    // create rdma context per connection.
    // use the global rdma_dev
    init_rdma_context(&rdma_ctx_, &rdma_dev);

    local_info_ = get_rdma_conn_info(&rdma_ctx_, &rdma_dev);

    print_rdma_conn_info(&local_info_, false);
    print_rdma_conn_info(&remote_info_, true);

    // Modify QP to RTR state
    if (modify_qp_to_rtr(&rdma_ctx_, &rdma_dev, &remote_info_)) {
        ERROR("Failed to modify QP to RTR");
        return -1;
    }

    if (modify_qp_to_rts(&rdma_ctx_)) {
        ERROR("Failed to modify QP to RTS");
        return -1;
    }

    INFO("RDMA exchange done");

    rdma_connected_ = true;

    if (posix_memalign((void **)&send_buffer_, 4096, PROTOCOL_BUFFER_SIZE) != 0) {
        ERROR("Failed to allocate send buffer");
        return SYSTEM_ERROR;
    }

    send_mr_ = ibv_reg_mr(rdma_dev.pd, send_buffer_, PROTOCOL_BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE);
    if (!send_mr_) {
        ERROR("Failed to register MR");
        return SYSTEM_ERROR;
    }

    for (int i = 0; i < MAX_RECV_WR; i++) {
        if (posix_memalign((void **)&recv_buffer_[i], 4096, PROTOCOL_BUFFER_SIZE) != 0) {
            ERROR("Failed to allocate recv buffer");
            return SYSTEM_ERROR;
        }

        recv_mr_[i] =
            ibv_reg_mr(rdma_dev.pd, recv_buffer_[i], PROTOCOL_BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE);
        if (!recv_mr_[i]) {
            ERROR("Failed to register MR");
            return SYSTEM_ERROR;
        }

        if (prepare_recv_rdma_request(i) < 0) {
            ERROR("Failed to prepare recv rdma request");
            return SYSTEM_ERROR;
        }
    }

    if (ibv_req_notify_cq(rdma_ctx_.cq, 0)) {
        ERROR("Failed to request notify for CQ");
        return SYSTEM_ERROR;
    }

    uv_poll_init(loop, &poll_handle_, rdma_ctx_.comp_channel->fd);
    poll_handle_.data = this;
    uv_poll_start(&poll_handle_, UV_READABLE | UV_WRITABLE,
                  [](uv_poll_t *handle, int status, int events) {
                      client_t *client = static_cast<client_t *>(handle->data);
                      client->cq_poll_handle(handle, status, events);
                  });

    // Send server's RDMA connection info to client
    send_resp(FINISH, &local_info_, sizeof(local_info_));
    reset_client_read_state();
    return 0;
}

// send_resp send fixed size response to client.
void Client::send_resp(int return_code, void *buf, size_t size) {
    if (size > 0) {
        assert(buf != NULL);
    }
    uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));

    tcp_send_buffer_ = (char *)realloc(tcp_send_buffer_, size + RETURN_CODE_SIZE);

    memcpy(tcp_send_buffer_, &return_code, RETURN_CODE_SIZE);
    memcpy(tcp_send_buffer_ + RETURN_CODE_SIZE, buf, size);
    write_req->data = this;
    uv_buf_t wbuf = uv_buf_init(tcp_send_buffer_, size + RETURN_CODE_SIZE);
    uv_write(write_req, (uv_stream_t *)handle_, &wbuf, 1, on_write);
}

int Client::check_key(const std::string &key_to_check) {
    int ret = 1;
    // check if the key exists and committed
    run_in_kv_thread([&]() { ret = kv_map.count(key_to_check) > 0 ? 0 : 1; });

    send_resp(FINISH, &ret, sizeof(ret));
    reset_client_read_state();
    return 0;
}

int Client::get_match_last_index(const GetMatchLastIndexRequest *request) {
    int left = 0;
    run_in_kv_thread([&]() {
        int l = 0, r = request->keys()->size();
        while (l < r) {
            int mid = l + (r - l) / 2;
            request->keys()->Get(mid);
            if (kv_map.count(request->keys()->Get(mid)->str())) {
                l = mid + 1;
            }
            else {
                r = mid;
            }
        }
        left = l - 1;
    });

    send_resp(FINISH, &left, sizeof(left));
    reset_client_read_state();
    return 0;
}

/**
 * The function deletes a list of keys in kv_map.
 *
 * Input:
 *     request: the request contains a list of the keys to delete
 *
 * Output:
 *     the actual count of the keys deleted.
 *
 * Return:
 *     success code
 *
 * NOTE: The function handles the runtime_error and continue for next key
 **/
int Client::delete_keys(const DeleteKeysRequest *request) {
    int count = 0;
    run_in_kv_thread([&]() {
        for (const auto *key : *request->keys()) {
            auto it = kv_map.find(key->str());
            if (it != kv_map.end()) {
                auto ptr = it->second;
                kv_map.erase(it);
                lru_queue.erase(ptr->lru_it);
                count++;
            }
        }
    });

    send_resp(FINISH, &count, sizeof(count));
    reset_client_read_state();
    return 0;
}

// return value of handle_request:
// if ret is less than 0, it is an system error, outer code will close the
// connection if ret is greater than 0, it is an application error or success
void handle_request(uv_stream_t *stream, client_t *client) {
    auto start = std::chrono::high_resolution_clock::now();
    int error_code = 0;
    // if error_code is not 0, close the connection
    switch (client->header_.op) {
        case OP_RDMA_EXCHANGE: {
            memcpy((void *)(&client->remote_info_), client->tcp_recv_buffer_,
                   client->expected_bytes_);
            error_code = client->rdma_exchange();
            break;
        }
        case OP_CHECK_EXIST: {
            std::string key_to_check(client->tcp_recv_buffer_, client->expected_bytes_);
            DEBUG("check key: {}", key_to_check);
            error_code = client->check_key(key_to_check);
            break;
        }
        case OP_GET_MATCH_LAST_IDX: {
            const GetMatchLastIndexRequest *request =
                GetGetMatchLastIndexRequest(client->tcp_recv_buffer_);
            error_code = client->get_match_last_index(request);
            break;
        }
        case OP_DELETE_KEYS: {
            DEBUG("delete keys...");
            const DeleteKeysRequest *request = GetDeleteKeysRequest(client->tcp_recv_buffer_);
            error_code = client->delete_keys(request);
            break;
        }
        case OP_TCP_PAYLOAD: {
            DEBUG("TCP GET/PUT data...");
            const TCPPayloadRequest *request = GetTCPPayloadRequest(client->tcp_recv_buffer_);
            error_code = client->tcp_payload_request(request);
            break;
        }
        default:
            ERROR("Invalid request");
            error_code = INVALID_REQ;
            break;
    }

    if (error_code != 0) {
        client->send_resp(error_code, NULL, 0);
        client->reset_client_read_state();
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;
}

void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    client_t *client = (client_t *)stream->data;
    ssize_t offset = 0;

    if (nread < 0) {
        if (nread != UV_EOF)
            ERROR("Read error {}", uv_err_name(nread));
        uv_close((uv_handle_t *)stream, on_close);
        goto clean_up;
    }

    while (offset < nread) {
        switch (client->state_) {
            case READ_HEADER: {
                size_t to_copy = MIN(nread - offset, FIXED_HEADER_SIZE - client->bytes_read_);
                memcpy(((char *)&client->header_) + client->bytes_read_, buf->base + offset,
                       to_copy);
                client->bytes_read_ += to_copy;
                offset += to_copy;
                if (client->bytes_read_ == FIXED_HEADER_SIZE) {
                    DEBUG("HEADER: op: {}, body_size :{}", client->header_.op,
                          (unsigned int)client->header_.body_size);

                    int ret = verify_header(&client->header_);
                    if (ret != 0) {
                        ERROR("Invalid header");
                        uv_close((uv_handle_t *)stream, on_close);
                        goto clean_up;
                    }
                    // prepare for reading body
                    client->expected_bytes_ = client->header_.body_size;
                    client->bytes_read_ = 0;
                    client->tcp_recv_buffer_ =
                        (char *)realloc(client->tcp_recv_buffer_, client->expected_bytes_);
                    client->state_ = READ_BODY;
                }
                break;
            }

            case READ_BODY: {
                assert(client->tcp_recv_buffer_ != NULL);

                DEBUG("reading body, bytes_read: {}, expected_bytes: {}", client->bytes_read_,
                      client->expected_bytes_);
                size_t to_copy = MIN(nread - offset, client->expected_bytes_ - client->bytes_read_);

                memcpy(client->tcp_recv_buffer_ + client->bytes_read_, buf->base + offset, to_copy);
                client->bytes_read_ += to_copy;
                offset += to_copy;
                if (client->bytes_read_ == client->expected_bytes_) {
                    DEBUG("body read done, size {}", client->expected_bytes_);
                    handle_request(stream, client);
                }
                break;
            }
            case READ_VALUE_THROUGH_TCP: {
                size_t to_copy = MIN(nread - offset, client->expected_bytes_ - client->bytes_read_);
                memcpy(client->current_tcp_task_->ptr + client->bytes_read_, buf->base + offset,
                       to_copy);
                client->bytes_read_ += to_copy;
                offset += to_copy;
                if (client->bytes_read_ == client->expected_bytes_) {
                    auto ptr = client->current_tcp_task_;
                    run_in_kv_thread([&ptr]() {
                        kv_map[ptr->key] = ptr;
                        // put the ptr into lru queue
                        lru_queue.push_back(ptr);
                        ptr->lru_it = --lru_queue.end();
                    });

                    client->current_tcp_task_.reset();
                    client->send_resp(FINISH, NULL, 0);
                    client->reset_client_read_state();
                }
                break;
            }
        }
    }
clean_up:
    free(buf->base);
}

void on_new_connection(uv_stream_t *server, int status) {
    INFO("new connection...");
    if (status < 0) {
        ERROR("New connection error {}", uv_strerror(status));
        return;
    }
    uv_tcp_t *client_handle = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));
    uv_tcp_init(loop, client_handle);
    if (uv_accept(server, (uv_stream_t *)client_handle) == 0) {
        client_t *client = new client_t();
        // TODO: use constructor
        client->handle_ = client_handle;
        client_handle->data = client;
        client->state_ = READ_HEADER;
        client->bytes_read_ = 0;
        client->expected_bytes_ = FIXED_HEADER_SIZE;
        uv_read_start((uv_stream_t *)client_handle, alloc_buffer, on_read);
    }
    else {
        uv_close((uv_handle_t *)client_handle, NULL);
    }
}

static void kv_poller_loop() {
    _kv_thread_id = std::this_thread::get_id();

    while (!_pipeline_stop.load()) {
        bool did_work = false;

        rdma_done_t *done = nullptr;
        int budget = 512;
        while (budget-- > 0 && _rdma_done_q.pop(done)) {
            did_work = true;
            done->client->handle_rdma_done(done);
            client_release(done->client);
            delete done;
        }

        kv_msg_t *msg = nullptr;
        budget = 128;
        while (budget-- > 0 && _recv_task_q.pop(msg)) {
            did_work = true;
            if (msg->kind == kv_msg_t::RECV_REQ) {
                recv_task_t *task = static_cast<recv_task_t *>(msg);
                client_t *client = task->client;

                if (client->closing_.load()) {
                    client_release(client);
                    delete task;
                    continue;
                }

                int ret = 0;
                switch (task->op) {
                    case OP_RDMA_WRITE: {
                        ret = client->write_rdma_cache(task);
                        break;
                    }
                    case OP_RDMA_READ: {
                        ret = client->read_rdma_cache(task);
                        break;
                    }
                    default:
                        ERROR("Unexpected request op: {}", task->op);
                        ret = INVALID_REQ;
                        break;
                }

                if (ret != 0) {
                    client->post_ack(ret);
                }
                client_release(client);
                delete task;
            }
            else {
                kv_sync_task_t *sync = static_cast<kv_sync_task_t *>(msg);
                sync->fn();
                sync->done.set_value();
            }
        }

        if (!did_work) {
            std::unique_lock<std::mutex> lock(_kv_mu);
            while (!_pipeline_stop.load() && _recv_task_q.empty() && _rdma_done_q.empty()) {
                if (_kv_cv.wait_for(lock, std::chrono::milliseconds(2)) ==
                    std::cv_status::timeout) {
                    break;
                }
            }
        }
    }
}

static void sq_submit_poller_loop() {
    std::deque<rdma_submit_t *> pending;

    while (!_pipeline_stop.load()) {
        bool did_work = false;

        ack_task_t *ack = nullptr;
        while (_ack_q.pop(ack)) {
            did_work = true;
            ack->client->post_ack_immediate(ack->return_code);
            client_release(ack->client);
            delete ack;
        }

        while (true) {
            if (pending.empty()) {
                rdma_submit_t *submit = nullptr;
                if (!_rdma_submit_q.pop(submit)) {
                    break;
                }
                pending.push_back(submit);
            }

            rdma_submit_t *submit = pending.front();
            if (submit->ops->empty()) {
                pending.pop_front();
                client_release(submit->client);
                delete submit->ops;
                delete submit;
                continue;
            }

            int submitted = submit->client->perform_batch_rdma(submit);

            if (submitted < 0) {
                pending.pop_front();
                rdma_done_t *done = new rdma_done_t();
                done->client = submit->client;
                done->wr_id = (uintptr_t)submit->ops;
                done->opcode = submit->opcode == IBV_WR_RDMA_READ ? IBV_WC_RDMA_READ
                                                                  : IBV_WC_RDMA_WRITE;
                done->status = IBV_WC_LOC_PROT_ERR;
                client_retain(done->client);
                while (!_rdma_done_q.push(done)) {
                    std::this_thread::yield();
                }
                _kv_cv.notify_one();

                client_release(submit->client);
                delete submit;
                continue;
            }

            if (submitted == 0) {
                break;
            }

            did_work = true;
            if (submit->offset >= submit->ops->size()) {
                pending.pop_front();
                client_release(submit->client);
                delete submit;
            }
        }

        if (!did_work) {
            std::unique_lock<std::mutex> lock(_sq_mu);
            while (!_pipeline_stop.load() && _ack_q.empty() && _rdma_submit_q.empty()) {
                if (_sq_cv.wait_for(lock, std::chrono::milliseconds(2)) ==
                    std::cv_status::timeout) {
                    break;
                }
            }
        }
    }

    for (auto *submit : pending) {
        delete submit->ops;
        client_release(submit->client);
        delete submit;
    }
    pending.clear();
}

static void start_pipeline() {
    _kv_running.store(true);
    _kv_thread = std::thread(kv_poller_loop);
    _kv_thread.detach();

    _sq_thread = std::thread(sq_submit_poller_loop);
    _sq_thread.detach();
}

int register_server(unsigned long loop_ptr, server_config_t config) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGBUS, signal_handler);
    signal(SIGFPE, signal_handler);
    signal(SIGILL, signal_handler);

    global_config = config;

    loop = uv_default_loop();

    loop = (uv_loop_t *)loop_ptr;
    assert(loop != NULL);
    uv_tcp_init(loop, &server);
    struct sockaddr_in addr;
    uv_ip4_addr("0.0.0.0", config.service_port, &addr);

    uv_tcp_bind(&server, (const struct sockaddr *)&addr, 0);
    int r = uv_listen((uv_stream_t *)&server, 128, on_new_connection);
    if (r) {
        fprintf(stderr, "Listen error: %s\n", uv_strerror(r));
        return -1;
    }

    INFO("open rdma device {}, link_type {}, hint_gid_index {},", config.dev_name, config.link_type,
         config.hint_gid_index);
    if (open_rdma_device(config.dev_name, config.ib_port, config.link_type, config.hint_gid_index,
                         &rdma_dev) < 0) {
        ERROR("Failed to open RDMA device");
        return -1;
    }
    mm = new MM(config.prealloc_size << 30, config.minimal_allocate_size << 10, rdma_dev.pd);

    start_pipeline();

    INFO("register server done");

    return 0;
}
