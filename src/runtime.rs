use std::thread;
use std::sync::Arc;
use std::time::{self, Duration};
use std::ops::{Deref, DerefMut};
// use std::iter;
use mio;
use anyhow::Result;
use parking_lot::RwLock;
use smallvec::SmallVec;
// use signal_hook;

const AVG_CORES: usize = 8;

// type Callback<TD> = dyn Fn(TD) -> Result<()> + Send + Sync;
pub type TimerEvHandler<TD> = dyn Fn(&mut RuntimeInstance<TD>) -> Result<()> + Send + Sync;
pub type SourceEvHandler<TD> = dyn Fn(&mut RuntimeInstance<TD>, &mut TD, &mio::event::Event) -> Result<()> + Send + Sync;

pub struct RuntimeInstance<TD: Send + Sync + 'static> {
    instance: Arc<RwLock<Runtime<TD>>>
}

pub struct Runtime<TD: Send + Sync + 'static> {
    nthreads: usize,
    wakers: SmallVec<[Arc<mio::Waker>; AVG_CORES]>,
    polls: SmallVec<[Option<mio::Poll>; AVG_CORES]>,
    join_handles: SmallVec<[Option<thread::JoinHandle<Result<()>>>; AVG_CORES]>,
    thread_data: SmallVec<[Option<TD>; AVG_CORES]>,
    // callbacks: SmallVec<[Box<TimerEvHandler>; 5]>,
    timer_events: Arc<RwLock<SmallVec<[TimerEvent<TD>; 10]>>>,
    source_handlers: SmallVec<[Arc<SourceEvent<TD>>; AVG_CORES * 2]>,
    next_token: usize,
    next_event_ix: usize,
    started: bool,
    should_exit: bool,
}

#[derive(Clone, Copy, PartialEq)]
struct EventIndex(usize);

/// Can trigger multiple times in rapid succession if multiple timer periods were missed
struct TimerEvent<TD: Send + Sync + 'static> {
    //TODO: cancelling
    #[allow(dead_code)]
    event_ix: EventIndex,
    // TODO: change to runtime shared data callback
    handler: Box<TimerEvHandler<TD>>,
    timer: Duration,
    next_trigger: time::Instant,
    last_triggered: Option<time::Instant>,
    repeat: bool,
}

// struct SignalEvent {
//     signal: std::os::raw::c_int,
// }

struct SourceEvent<TD: Send + Sync + 'static> {
    source_id: mio::Token,
    handler: Box<SourceEvHandler<TD>>
}

fn wake_all<'a, T: Iterator<Item=&'a Arc<mio::Waker>>>(wakers: T) {
    for waker in wakers {
        waker.wake().ok();
    }
}

 impl<TD: Send + Sync + 'static> Deref for RuntimeInstance<TD> {
    type Target = Arc<RwLock<Runtime<TD>>>;
    fn deref(&self) -> &Self::Target {
        &self.instance
    }
}

impl<TD: Send + Sync + 'static> DerefMut for RuntimeInstance<TD> {
    fn deref_mut(&mut self) -> &mut Arc<RwLock<Runtime<TD>>> {
        &mut self.instance
    }
}

impl<TD: Send + Sync + 'static> From<Arc<RwLock<Runtime<TD>>>> for RuntimeInstance<TD> {
    fn from(src: Arc<RwLock<Runtime<TD>>>) -> Self {
        RuntimeInstance { instance: src }
    }
}

impl<TD: Send + Sync + 'static> RuntimeInstance<TD> {
    /// if repeat is true, the timer becomes periodic until cancelled
    #[allow(dead_code)]
    pub fn register_timer_event<>(&self, timer: time::Duration,  repeat: bool, handler: Box<TimerEvHandler<TD>>) 
    where TD: Send + Sync + 'static {
        let mut rwrite = self.instance.write();
        let rt_cloned = Arc::downgrade(&self.instance);
    
        let event_ix = rwrite.get_next_event_ix();
        let next_trigger = time::Instant::now() + timer;
    
        let timer_ev = TimerEvent { 
            event_ix, handler, repeat, last_triggered: None, timer, next_trigger 
        };
        rwrite.timer_events.write().push(timer_ev);
    
        thread::spawn(move || -> Result<()> {
            loop { 
                thread::sleep(timer);
                // println!("Waking");
                if let Some(rt_cloned) = rt_cloned.upgrade() {
                    if rt_cloned.read().should_exit { break; }
    
                    let wakers: SmallVec<[Arc<mio::Waker>; AVG_CORES]> = rt_cloned.read().wakers.iter().cloned().collect();
                    wake_all(wakers.iter());
                    if !repeat {
                        break;
                    }
                } else { break; }
                // TODO: cancellation check here
                // for event in runtime.write().timer_events.iter_mut().filter(
                //     |item| { item.event_ix == event_ix }) {
                //     event.handled = false;
                // }
            }
            Ok(())
        });
        // rwrite.join_handles.push(Some(handle));
    }

    #[inline]
    fn trigger_timer_event(&mut self, event: &mut TimerEvent<TD>, delay: time::Duration) -> Result<()> {
        event.last_triggered = Some(event.next_trigger + delay);
        event.next_trigger += event.timer;
        (*event.handler)(self)?;
        Ok(())
    }

    fn handle_timer_events(&mut self, timer_events: &mut SmallVec<[TimerEvent<TD>; 10]>) -> Result<()> {
        let now = time::Instant::now();
        let timer_events = timer_events.iter_mut()
            .filter_map(|event| { 
                if let Some(delay) = now.checked_duration_since(event.next_trigger) {
                    Some((event, delay))
                } else { None }});
        for (event, delay) in timer_events {
            self.trigger_timer_event(event, delay)?;
        }
        Ok(())
    }

    pub fn send_stop_signal(&self) {
        self.instance.write().should_exit = true;
        wake_all(self.instance.read().wakers.iter());
    }
    
    pub fn block_until_finished(self) -> Result<()> {
        let join_handles: SmallVec<[thread::JoinHandle<Result<()>>; AVG_CORES]> = self.instance.write().join_handles.iter_mut()
            .map(|item| { item.take().unwrap() }).collect();
        for handle in join_handles {
            handle.join().unwrap()?;
        }
        Ok(())
    }
}

impl<TD: Send + Sync + 'static> Runtime<TD> {
    pub fn new(nthreads: usize) -> Result<Self> {
        let mut runtime = Runtime {
            polls: SmallVec::with_capacity(nthreads),
            wakers: SmallVec::with_capacity(nthreads),
            join_handles: SmallVec::with_capacity(nthreads),
            thread_data: SmallVec::with_capacity(nthreads),
            timer_events: Arc::new(RwLock::new(SmallVec::new())),
            source_handlers: SmallVec::new(),
            nthreads,
            next_token: 0,
            next_event_ix: 0,
            started: false,
            should_exit: false,
            // callbacks: SmallVec::new(),
        };

        for _ in 0..nthreads {
            let poll = mio::Poll::new()?;
            let waker = mio::Waker::new(poll.registry(), runtime.get_next_token())?;

            runtime.polls.push(Some(poll));
            runtime.wakers.push(Arc::new(waker));

            runtime.thread_data.push(None);
        }

        Ok(runtime)
    }

    // #[allow(dead_code)]
    // pub fn register_callback(&mut self, cb: Box<TimerEvHandler>) {
    //     self.callbacks.push(Box::new(cb));
    // }

    /// if interests: None, defaults to READABLE + WRITABLE
    pub fn register_event_source<S>(&mut self, source: &mut S, interests: Option<mio::Interest>, 
        thread_id: usize) -> Result<mio::Token>
    where S: mio::event::Source 
    {
        if thread_id >= self.nthreads {
            panic!("Can't register source with an unitialized thread");
        }
        let source_token = self.get_next_token();
        let interests = interests.unwrap_or(mio::Interest::READABLE.add(mio::Interest::WRITABLE));

        if let Some(poll) = &self.polls[thread_id] {
            poll.registry().register(source, source_token, interests)?;
        }
        Ok(source_token)
    }

    // TODO: partition per poll / thread
    pub fn register_source_event_handler(&mut self, token: mio::Token, handler: Box<SourceEvHandler<TD>>) {
        self.source_handlers.push(Arc::new(SourceEvent {
            source_id: token,
            handler
        }));
    }

    pub fn set_thread_data(&mut self, thread_ix: usize, data: TD) {
        if self.started {
            panic!("Can't set thread data on a running runtime");
        }
        self.thread_data[thread_ix] = Some(data);
    }

    fn prune_timer_events(timer_events: &mut SmallVec<[TimerEvent<TD>; 10]> ) {
        let now = time::Instant::now();
        timer_events.retain(|event| {
            match now.checked_duration_since(event.next_trigger) {
                None if event.last_triggered == None => true,
                None | Some(_) => event.repeat,
            }
        });
    }

    fn executor_loop_factory(mut instance: RuntimeInstance<TD>, poll: mio::Poll, thread_data: TD, thread_ix: usize)
        -> impl FnOnce() -> Result<()>
    { move || { 
        let mut poll = poll;
        let mut thread_data = thread_data;
        let mut events = mio::Events::with_capacity(1000);

        // for cb in &runtime.read().callbacks {
        //     cb();
        // }
        
        #[allow(unused_labels)]
        'event_loop: loop {
            poll.poll(&mut events, None)?;
            for event in events.iter() {
                let handlers: SmallVec<[Arc<SourceEvent<TD>>; 1]> = instance.read().source_handlers.iter()
                    .filter(|source_ev| { source_ev.source_id == event.token() })
                    .cloned().collect();
                for source_ev in handlers {
                    (*source_ev.handler)(&mut instance, &mut thread_data, event)?;
                }
                // Token(thread_ix) is Waker
                if event.token() == mio::Token(thread_ix) {
                    // println!("Thread {} awoken.", thread_ix);
                    let timer_events = instance.read().timer_events.clone();
                    // acts like a Mutex to prevent double triggering
                    let mut timer_ev_write = timer_events.write();
                    instance.handle_timer_events(&mut timer_ev_write)?;
                    Self::prune_timer_events(&mut timer_ev_write);
                    drop(timer_ev_write);

                    if instance.read().should_exit {
                        break 'event_loop;
                    }
                }
            }
        }
        #[allow(unreachable_code)]
        Ok(())
    }}

    pub fn start(self) -> RuntimeInstance<TD> {
        let runtime = RuntimeInstance { instance: Arc::new(RwLock::new(self)) };
        let mut rwrite = runtime.write();

        for i in 0..rwrite.nthreads {
            let handle = thread::spawn(Self::executor_loop_factory(runtime.clone().into(), 
                rwrite.polls[i].take().unwrap(), rwrite.thread_data[i].take().unwrap(), i));

            rwrite.join_handles.push(Some(handle));
        }

        rwrite.started = true;
        drop(rwrite);
        runtime
    }

    fn get_next_token(&mut self) -> mio::Token {
        let next_token = self.next_token;
        self.next_token += 1;
        mio::Token(next_token)
    }

    #[allow(dead_code)]
    fn get_next_event_ix(&mut self) -> EventIndex {
        let next_ix = self.next_event_ix;
        self.next_event_ix += 1;
        EventIndex(next_ix)   
    }
}