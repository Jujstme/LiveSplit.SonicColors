#![no_std]
use asr::{signature::Signature, time::Duration, timer, timer::TimerState, watcher::Watcher, Address, Process};

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
        let Some(addresses) = &game.addresses else {
            game.addresses = MemoryPtr::new(&game.game, game.main_module_base, game.main_module_size);
            return;
        };

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
            base_address: Address(ptr),
        })
    }
}

#[no_mangle]
pub extern "C" fn update() {
    AUTOSPLITTER.lock().update();
}

fn update_internal(game: &Process, addresses: &MemoryPtr, watchers: &mut Watchers) {
    let level_id = game.read_pointer_path64::<[u8; 6]>(addresses.base_address.0, &[0, 0x8, 0x38, 0x60, 0xE0]);
    let level = match &level_id {
        Ok(x) => match x {
            b"stg110" => Levels::TropicalResortAct1,
            b"stg130" => Levels::TropicalResortAct2,
            b"stg120" => Levels::TropicalResortAct3,
            b"stg140" => Levels::TropicalResortAct4,
            b"stg150" => Levels::TropicalResortAct5,
            b"stg160" => Levels::TropicalResortAct6,
            b"stg190" => Levels::TropicalResortBoss,
            b"stg210" => Levels::SweetMountainAct1,
            b"stg230" => Levels::SweetMountainAct2,
            b"stg220" => Levels::SweetMountainAct3,
            b"stg260" => Levels::SweetMountainAct4,
            b"stg240" => Levels::SweetMountainAct5,
            b"stg250" => Levels::SweetMountainAct6,
            b"stg290" => Levels::SweetMountainBoss,
            b"stg310" => Levels::StarlightCarnivalAct1,
            b"stg330" => Levels::StarlightCarnivalAct2,
            b"stg340" => Levels::StarlightCarnivalAct3,
            b"stg350" => Levels::StarlightCarnivalAct4,
            b"stg320" => Levels::StarlightCarnivalAct5,
            b"stg360" => Levels::StarlightCarnivalAct6,
            b"stg390" => Levels::StarlightCarnivalBoss,
            b"stg410" => Levels::PlanetWispAct1,
            b"stg440" => Levels::PlanetWispAct2,
            b"stg450" => Levels::PlanetWispAct3,
            b"stg430" => Levels::PlanetWispAct4,
            b"stg460" => Levels::PlanetWispAct5,
            b"stg420" => Levels::PlanetWispAct6,
            b"stg490" => Levels::PlanetWispBoss,
            b"stg510" => Levels::AquariumParkAct1,
            b"stg540" => Levels::AquariumParkAct2,
            b"stg550" => Levels::AquariumParkAct3,
            b"stg530" => Levels::AquariumParkAct4,
            b"stg560" => Levels::AquariumParkAct5,
            b"stg520" => Levels::AquariumParkAct6,
            b"stg590" => Levels::AquariumParkBoss,
            b"stg610" => Levels::AsteroidCoasterAct1,
            b"stg630" => Levels::AsteroidCoasterAct2,
            b"stg640" => Levels::AsteroidCoasterAct3,
            b"stg650" => Levels::AsteroidCoasterAct4,
            b"stg660" => Levels::AsteroidCoasterAct5,
            b"stg620" => Levels::AsteroidCoasterAct6,
            b"stg690" => Levels::AsteroidCoasterBoss,
            b"stg710" => Levels::TerminalVelocityAct1,
            b"stg790" => Levels::TerminalVelocityBoss,
            b"stg720" => Levels::TerminalVelocityAct2,
            b"stgD10" => Levels::SonicSimulatorAct1_1,
            b"stgB20" => Levels::SonicSimulatorAct1_2,
            b"stgE50" => Levels::SonicSimulatorAct1_3,
            b"stgD20" => Levels::SonicSimulatorAct2_1,
            b"stgB30" => Levels::SonicSimulatorAct2_2,
            b"stgF30" => Levels::SonicSimulatorAct2_3,
            b"stgG10" => Levels::SonicSimulatorAct3_1,
            b"stgG30" => Levels::SonicSimulatorAct3_2,
            b"stgA10" => Levels::SonicSimulatorAct3_3,
            b"stgD30" => Levels::SonicSimulatorAct4_1,
            b"stgG20" => Levels::SonicSimulatorAct4_2,
            b"stgC50" => Levels::SonicSimulatorAct4_3,
            b"stgE30" => Levels::SonicSimulatorAct5_1,
            b"stgB10" => Levels::SonicSimulatorAct5_2,
            b"stgE40" => Levels::SonicSimulatorAct5_3,
            b"stgG40" => Levels::SonicSimulatorAct6_1,
            b"stgC40" => Levels::SonicSimulatorAct6_2,
            b"stgF40" => Levels::SonicSimulatorAct6_3,
            b"stgA30" => Levels::SonicSimulatorAct7_1,
            b"stgE20" => Levels::SonicSimulatorAct7_2,
            b"stgC10" => Levels::SonicSimulatorAct7_3,
            _ => Levels::None
        },
        _ => Levels::None,
    };
    watchers.levelid.update(Some(level));

    if level == Levels::None {
        watchers.igt.update(Some(Duration::ZERO));
        watchers.goalringreached.update(Some(false));
    } else {
        watchers.igt.update(Some(Duration::milliseconds((game.read_pointer_path64::<f32>(addresses.base_address.0, &[0, 0x8, 0x38, 0x60, 0x270]).unwrap_or_default() * 100.0) as i64 * 10)));
        watchers.goalringreached.update(Some((game.read_pointer_path64::<u8>(addresses.base_address.0, &[0, 0x8, 0x38, 0x60, 0x110]).unwrap_or_default() & (1 << 5)) != 0));    
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

#[derive(Clone, Copy, PartialEq)]
enum GameMode {
    AnyPercent,
    EggShuttle
}

#[derive(Clone, Copy, PartialEq)]
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

/*
fn get_string_utf8(input: &[u8]) -> &str {
    str::from_utf8(&input[0..input.iter().position(|&c| c == b'\0').unwrap_or(input.len())]).unwrap_or("")
}
*/