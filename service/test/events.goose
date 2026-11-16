// service: running as one, from a console: begin() says interactive (or
// service, under a service manager), requests queue up in order, wait()
// times out with EV_NONE, SIGTERM and SIGHUP (POSIX) arrive as EV_STOP and
// EV_RELOAD, and begin() twice is refused.

import std;
import os;
import gslib from "../..";
import gslib.service;

fn main() {
    let mode = service::begin("goose-test-events", true);
    assert(mode == service::MODE_INTERACTIVE || mode == service::MODE_SERVICE);
    assert(service::begin("goose-test-events") == -service::ERR_STATE);

    // Nothing queued: the wait times out, after about as long as asked.
    let t0 = clock_ns();
    assert(service::wait(50) == service::EV_NONE);
    let ms = (clock_ns() - t0) / 1000000;
    assert(ms >= 40 && ms < 5000);
    assert(service::wait(0) == service::EV_NONE);

    // Queued requests come out in order, none lost.
    for ev in [service::EV_RELOAD, service::EV_PAUSE, service::EV_CONTINUE, service::EV_SHUTDOWN, service::EV_STOP] {
        assert(service::inject(ev) == service::OK);
    }
    assert(service::wait(1000) == service::EV_RELOAD);
    assert(service::wait(1000) == service::EV_PAUSE);
    assert(service::wait(1000) == service::EV_CONTINUE);
    let sd = service::wait(1000);
    assert(sd == service::EV_SHUTDOWN && service::is_stop(sd));
    assert(service::wait(1000) == service::EV_STOP);
    assert(service::wait(0) == service::EV_NONE);
    assert(service::inject(0) == service::ERR_ARG);
    assert(service::inject(9) == service::ERR_ARG);
    assert(!service::is_stop(service::EV_RELOAD));

    // The real signals, where there are any.
    if service::platform() != service::PLATFORM_WINDOWS {
        assert(service::raise(service::EV_RELOAD) == service::OK);
        assert(service::wait(2000) == service::EV_RELOAD);
        assert(service::raise(service::EV_STOP) == service::OK);
        assert(service::wait(2000) == service::EV_STOP);
        assert(service::raise(service::EV_STOP) == service::OK);
        assert(service::raise(service::EV_STOP) == service::OK);
        assert(service::wait(2000) == service::EV_STOP);
        assert(service::wait(2000) == service::EV_STOP);
    } else {
        assert(service::raise(service::EV_STOP) == service::ERR_UNSUPPORTED);
    }
    service::log("goose-test-events", service::LOG_INFO, "events: done");
    service::end(0);
    print("ok");
}
