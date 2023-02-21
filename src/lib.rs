#![no_std]
extern crate alloc;
use alloc::str;
use asr::{signature::Signature, time::Duration, timer, timer::TimerState, watcher::Watcher, Address, Process};
use lol_alloc::{FreeListAllocator, LockedAllocator};

#[global_allocator]
static ALLOCATOR: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

#[cfg(all(not(test), target_arch = "wasm32"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

static AUTOSPLITTER: spinning_top::Spinlock<State> = spinning_top::const_spinlock(State {
    game: None,
    watchers: Watchers {
        levelid: Watcher::new(),
        igt: Watcher::new(),
        goalringreached: Watcher::new(),
        eggshuttle_totalstages: Watcher::new(),
        eggshuttle_progressiveid: Watcher::new(),
        runstart: Watcher::new(),
        tr1rank: Watcher::new(),
        accumulatedigt: Duration::ZERO,
        currentgamemode: GameMode::AnyPercent,
    },
    // settings: None,
});

struct State {
    game: Option<ProcessInfo>,
    watchers: Watchers,
    // settings: Settings,
}

struct ProcessInfo {
    game: Process,
    main_module_base: Address,
    main_module_size: u64,
    addresses: Option<MemoryPtr>,
}

struct Watchers {
    levelid: Watcher<Levels>,
    igt: Watcher<Duration>,
    goalringreached: Watcher<bool>,
    eggshuttle_totalstages: Watcher<u8>,
    eggshuttle_progressiveid: Watcher<u8>,
    runstart: Watcher<u8>,
    tr1rank: Watcher<i8>,
    accumulatedigt: Duration,
    currentgamemode: GameMode,
}

struct MemoryPtr {
    base_address: Address,
}

impl State {
    fn attach_process() -> Option<ProcessInfo> {
        const PROCESS_NAMES: [&str; 2] = ["SonicColorsUltimate.exe", "Sonic Colors - Ultimate.exe"];
        let mut proc: Option<Process> = None;
        let mut proc_name: &str = "";
    
        for name in PROCESS_NAMES {
            proc = Process::attach(name);
            if proc.is_some() {
                proc_name = name;
                break;
            }
        }
    
        let game = proc?;
        let main_module_base = game.get_module_address(proc_name).ok()?;
        let main_module_size: u64 = 0x1BC50000; // Hack, until we can actually query ModuleMemorySize
    
        Some(ProcessInfo {
            game,
            main_module_base,
            main_module_size,
            addresses: None,
        })
    }

    fn update(&mut self) {
        // Checks is LiveSplit is currently attached to a target process and runs attach_process() otherwise
        if self.game.is_none() {
            self.game = State::attach_process()
        }
        let Some(game) = &mut self.game else { return };

        if !game.game.is_open() {
            self.game = None;
            return;
        }

        // Get memory addresses
        let Some(addresses) = &game.addresses else { game.addresses = MemoryPtr::new(&game.game, game.main_module_base, game.main_module_size); return; };

        // Update the watchers variables
        let game = &game.game;
        update_internal(game, addresses, &mut self.watchers);

        let timer_state = timer::state();
        if timer_state == TimerState::Running || timer_state == TimerState::Paused {
            //if is_loading(self) {
                timer::pause_game_time();
            //} else {
            //    timer::resume_game_time()
            //}

            timer::set_game_time(game_time(self));
            if reset(self) {
                timer::reset()
            } else if split(self) {
                timer::split()
            }
        } 

        if timer_state == TimerState::NotRunning {
            if start(self) {
                timer::start();
            }
        }     
    }    
}

impl MemoryPtr {
    fn new(process: &Process, addr: Address, size: u64) -> Option<Self> {
        const SIG: Signature<5> = Signature::new("76 0C 48 8B 0D");
        let mut ptr = SIG.scan_process_range(process, addr, size)?.0 + 5;
        ptr += 0x4 + process.read::<u32>(Address(ptr)).ok()? as u64;

        Some(Self {
            base_address: Address(ptr)
        })
    }
}

#[no_mangle]
pub extern "C" fn update() {
    AUTOSPLITTER.lock().update();
}

fn update_internal(game: &Process, addresses: &MemoryPtr, watchers: &mut Watchers) {
    let level_id = game.read_pointer_path64::<[u8; 6]>(addresses.base_address.0, &[0, 0x8, 0x38, 0x60, 0xE0]);
    if !level_id.is_ok() {
        watchers.levelid.update(Some(Levels::None));
        watchers.igt.update(Some(Duration::ZERO));
        watchers.goalringreached.update(Some(false));
    } else {
        let level_id = level_id.ok();
        let Some(level) = level_id else { return };
        let Some(level) =  str::from_utf8(&level).ok() else { return };

        let level: Levels = match level {
            "stg110" => Levels::TropicalResortAct1,
            "stg130" => Levels::TropicalResortAct2,
            "stg120" => Levels::TropicalResortAct3,
            "stg140" => Levels::TropicalResortAct4,
            "stg150" => Levels::TropicalResortAct5,
            "stg160" => Levels::TropicalResortAct6,
            "stg190" => Levels::TropicalResortBoss,
            "stg210" => Levels::SweetMountainAct1,
            "stg230" => Levels::SweetMountainAct2,
            "stg220" => Levels::SweetMountainAct3,
            "stg260" => Levels::SweetMountainAct4,
            "stg240" => Levels::SweetMountainAct5,
            "stg250" => Levels::SweetMountainAct6,
            "stg290" => Levels::SweetMountainBoss,
            "stg310" => Levels::StarlightCarnivalAct1,
            "stg330" => Levels::StarlightCarnivalAct2,
            "stg340" => Levels::StarlightCarnivalAct3,
            "stg350" => Levels::StarlightCarnivalAct4,
            "stg320" => Levels::StarlightCarnivalAct5,
            "stg360" => Levels::StarlightCarnivalAct6,
            "stg390" => Levels::StarlightCarnivalBoss,
            "stg410" => Levels::PlanetWispAct1,
            "stg440" => Levels::PlanetWispAct2,
            "stg450" => Levels::PlanetWispAct3,
            "stg430" => Levels::PlanetWispAct4,
            "stg460" => Levels::PlanetWispAct5,
            "stg420" => Levels::PlanetWispAct6,
            "stg490" => Levels::PlanetWispBoss,
            "stg510" => Levels::AquariumParkAct1,
            "stg540" => Levels::AquariumParkAct2,
            "stg550" => Levels::AquariumParkAct3,
            "stg530" => Levels::AquariumParkAct4,
            "stg560" => Levels::AquariumParkAct5,
            "stg520" => Levels::AquariumParkAct6,
            "stg590" => Levels::AquariumParkBoss,
            "stg610" => Levels::AsteroidCoasterAct1,
            "stg630" => Levels::AsteroidCoasterAct2,
            "stg640" => Levels::AsteroidCoasterAct3,
            "stg650" => Levels::AsteroidCoasterAct4,
            "stg660" => Levels::AsteroidCoasterAct5,
            "stg620" => Levels::AsteroidCoasterAct6,
            "stg690" => Levels::AsteroidCoasterBoss,
            "stg710" => Levels::TerminalVelocityAct1,
            "stg790" => Levels::TerminalVelocityBoss,
            "stg720" => Levels::TerminalVelocityAct2,
            "stgD10" => Levels::SonicSimulatorAct1_1,
            "stgB20" => Levels::SonicSimulatorAct1_2,
            "stgE50" => Levels::SonicSimulatorAct1_3,
            "stgD20" => Levels::SonicSimulatorAct2_1,
            "stgB30" => Levels::SonicSimulatorAct2_2,
            "stgF30" => Levels::SonicSimulatorAct2_3,
            "stgG10" => Levels::SonicSimulatorAct3_1,
            "stgG30" => Levels::SonicSimulatorAct3_2,
            "stgA10" => Levels::SonicSimulatorAct3_3,
            "stgD30" => Levels::SonicSimulatorAct4_1,
            "stgG20" => Levels::SonicSimulatorAct4_2,
            "stgC50" => Levels::SonicSimulatorAct4_3,
            "stgE30" => Levels::SonicSimulatorAct5_1,
            "stgB10" => Levels::SonicSimulatorAct5_2,
            "stgE40" => Levels::SonicSimulatorAct5_3,
            "stgG40" => Levels::SonicSimulatorAct6_1,
            "stgC40" => Levels::SonicSimulatorAct6_2,
            "stgF40" => Levels::SonicSimulatorAct6_3,
            "stgA30" => Levels::SonicSimulatorAct7_1,
            "stgE20" => Levels::SonicSimulatorAct7_2,
            "stgC10" => Levels::SonicSimulatorAct7_3,
            _ => Levels::None
        };
        watchers.levelid.update(Some(level));

        let Some(igt) = game.read_pointer_path64::<f32>(addresses.base_address.0, &[0, 0x8, 0x38, 0x60, 0x270]).ok() else { return };        
        watchers.igt.update(Some(Duration::milliseconds((igt * 100.0) as i64 * 10)));

        let Some(grr) = game.read_pointer_path64::<u8>(addresses.base_address.0, &[0, 0x8, 0x38, 0x60, 0x110]).ok() else { return };
        watchers.goalringreached.update(Some((grr & (1 << 5)) != 0));
    }

    let eggsh = game.read_pointer_path64::<u8>(addresses.base_address.0, &[0, 0x8, 0x38, 0x68, 0x110, 0x0]);
    if !eggsh.is_ok() {
        watchers.eggshuttle_progressiveid.update(Some(0));
        watchers.eggshuttle_totalstages.update(Some(0));
    } else {
        watchers.eggshuttle_totalstages.update(eggsh.ok());
        watchers.eggshuttle_progressiveid.update(game.read_pointer_path64(addresses.base_address.0, &[0, 0x8, 0x38, 0x68, 0x110, 0xB8]).ok());
    }

    let runstart = game.read_pointer_path64::<u8>(addresses.base_address.0, &[0, 0x8, 0x8, 0x10, 0x60, 0x120]);
    if !runstart.is_ok() {
        watchers.runstart.update(Some(0));
        watchers.tr1rank.update(Some(0));
    } else {
        watchers.runstart.update(runstart.ok());
        watchers.tr1rank.update(game.read_pointer_path64(addresses.base_address.0, &[0, 0x8, 0x8, 0x10, 0x60, 0x1CC]).ok());
    }

    // Adjusting other stuff
    if timer::state() == TimerState::NotRunning {
        if watchers.accumulatedigt != Duration::ZERO {
            watchers.accumulatedigt = Duration::ZERO
        }

        let Some(eggshuttlecount) = &watchers.eggshuttle_totalstages.pair else { return };
        if eggshuttlecount.current > 0 && eggshuttlecount.current <= 45 {
            watchers.currentgamemode = GameMode::EggShuttle
        } else {
            watchers.currentgamemode = GameMode::AnyPercent
        }
    }

    let Some(igt) = &watchers.igt.pair else { return };
    if igt.old != Duration::ZERO && igt.current == Duration::ZERO {
        watchers.accumulatedigt += igt.old
    }
}

fn start(state: &State) -> bool {
    let Some(level_id) = &state.watchers.levelid.pair else { return false };
    let Some(igt) = &state.watchers.igt.pair else { return false };
    let Some(runstart) = &state.watchers.runstart.pair else { return false };
    let Some(tr1rank) = &state.watchers.tr1rank.pair else { return false };

    match state.watchers.currentgamemode {
        GameMode::EggShuttle => level_id.current == Levels::TropicalResortAct1 && (level_id.old == Levels::None || (igt.old > asr::time::Duration::ZERO && igt.current == asr::time::Duration::ZERO)),
        _ => (tr1rank.current == -1 && runstart.old == 35 && runstart.current == 110)
            || (level_id.current == Levels::SonicSimulatorAct1_1 && level_id.old == Levels::None),
    }
}

fn split(state: &State) -> bool {
    let Some(goal_ring) = &state.watchers.goalringreached.pair else { return false };

    if state.watchers.currentgamemode == GameMode::EggShuttle {
        let Some(progressiveid) = &state.watchers.eggshuttle_progressiveid.pair else { return false };
        let Some(totalstages) = &state.watchers.eggshuttle_totalstages.pair else { return false };

        if progressiveid.old == totalstages.current - 1 {
            goal_ring.current && !goal_ring.old
        } else {
            progressiveid.current == progressiveid.old + 1
        }
    } else {
        let Some(level_id) = &state.watchers.levelid.pair else { return false };

        if level_id.old == Levels::TerminalVelocityAct2 {
            goal_ring.current && !goal_ring.old
        } else {
            !goal_ring.current && goal_ring.old && level_id.current != level_id.old
        }
    }
}

fn reset(state: &State) -> bool {
    if state.watchers.currentgamemode == GameMode::EggShuttle {
        let Some(igt) = &state.watchers.igt.pair else { return false };
        let Some(goal_ring) = &state.watchers.goalringreached.pair else { return false };
        igt.old != Duration::ZERO && igt.current == Duration::ZERO && !goal_ring.old
    } else {
        let Some(runstart) = &state.watchers.runstart.pair else { return false };
        runstart.old == 110 && runstart.current == 35
    }
}

fn game_time(state: &State) -> Duration {
    let Some(igt) = &state.watchers.igt.pair else { return Duration::ZERO };
    igt.current + state.watchers.accumulatedigt
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum GameMode {
    AnyPercent,
    EggShuttle
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Levels {
    TropicalResortAct1,
    TropicalResortAct2,
    TropicalResortAct3,
    TropicalResortAct4,
    TropicalResortAct5,
    TropicalResortAct6,
    TropicalResortBoss,
    SweetMountainAct1,
    SweetMountainAct2,
    SweetMountainAct3,
    SweetMountainAct4,
    SweetMountainAct5,
    SweetMountainAct6,
    SweetMountainBoss,
    StarlightCarnivalAct1,
    StarlightCarnivalAct2,
    StarlightCarnivalAct3,
    StarlightCarnivalAct4,
    StarlightCarnivalAct5,
    StarlightCarnivalAct6,
    StarlightCarnivalBoss,
    PlanetWispAct1,
    PlanetWispAct2,
    PlanetWispAct3,
    PlanetWispAct4,
    PlanetWispAct5,
    PlanetWispAct6,
    PlanetWispBoss,
    AquariumParkAct1,
    AquariumParkAct2,
    AquariumParkAct3,
    AquariumParkAct4,
    AquariumParkAct5,
    AquariumParkAct6,
    AquariumParkBoss,
    AsteroidCoasterAct1,
    AsteroidCoasterAct2,
    AsteroidCoasterAct3,
    AsteroidCoasterAct4,
    AsteroidCoasterAct5,
    AsteroidCoasterAct6,
    AsteroidCoasterBoss,
    TerminalVelocityAct1,
    TerminalVelocityBoss,
    TerminalVelocityAct2,
    SonicSimulatorAct1_1,
    SonicSimulatorAct1_2,
    SonicSimulatorAct1_3,
    SonicSimulatorAct2_1,
    SonicSimulatorAct2_2,
    SonicSimulatorAct2_3,
    SonicSimulatorAct3_1,
    SonicSimulatorAct3_2,
    SonicSimulatorAct3_3,
    SonicSimulatorAct4_1,
    SonicSimulatorAct4_2,
    SonicSimulatorAct4_3,
    SonicSimulatorAct5_1,
    SonicSimulatorAct5_2,
    SonicSimulatorAct5_3,
    SonicSimulatorAct6_1,
    SonicSimulatorAct6_2,
    SonicSimulatorAct6_3,
    SonicSimulatorAct7_1,
    SonicSimulatorAct7_2,
    SonicSimulatorAct7_3,
    None,
}