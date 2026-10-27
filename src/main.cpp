// Fixes the crash at SkyrimSE.exe+070DB20 on 1.6.1170 (null + 0x8 under Actor::CalculateCurrentHitTargetForWeaponSwing)
// with Precision - Accurate Melee Collisions 2.0.6. Precision queues a melee hit at its contact and runs it on a later
// update (PendingHit::Run). If the attacker was disabled or unloaded in between (a script, a cell change), it has no
// AI process: Run hands it to CalculateCurrentHitTargetForWeaponSwing, which reads through the missing process, and
// Run's hitstop reads currentProcess->high. The plugin wraps PendingHit::Run in Precision.dll and drops a hit whose
// attacker has no process - there is no attacker left to apply it. The same check is upstream as
// https://github.com/ersh1/Precision/pull/6; this plugin is for the released 2.0.6 build only (matched by its PE
// timestamp and the function's first bytes) and stays inactive for any other build.

namespace
{
	constexpr std::uint32_t                  kTimestamp = 0x6A967CB2;  // Precision.dll 2.0.6 (Nexus 72347)
	constexpr std::uintptr_t                 kRun = 0x5CA50;           // PendingHit::Run (Precision.pdb)
	// mov rax,rsp / mov [rax+10h],rbx / mov [rax+18h],rsi / mov [rax+20h],rdi - position-independent, moved to the stub
	constexpr std::array<std::uint8_t, 15>   kPrologue{ 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48, 0x89, 0x70, 0x18,
		  0x48, 0x89, 0x78, 0x20 };
	std::atomic<std::uint64_t>               skipped{ 0 };

	bool Milestone(std::uint64_t a_n)  // 1, 10, 100, ...
	{
		while (a_n % 10 == 0) {
			a_n /= 10;
		}
		return a_n == 1;
	}

	struct PendingHit
	{
		RE::NiPointer<RE::Actor> attacker;  // first member in 2.0.6
	};

	void (*Run)(PendingHit*) = nullptr;  // the original, through the stub below

	void RunThunk(PendingHit* a_hit)
	{
		const auto* attacker = a_hit->attacker.get();
		if (!attacker || !attacker->GetActorRuntimeData().currentProcess) {
			if (const auto n = ++skipped; Milestone(n)) {
				logger::info("pending hit of {:08X} dropped: the attacker has no AI process ({} so far)"sv,
					attacker ? attacker->GetFormID() : 0, n);
			}
			return;
		}
		Run(a_hit);
	}

	void AbsJump(std::uint8_t* a_at, std::uintptr_t a_to)  // jmp qword ptr [rip+0] / dq a_to - 14 bytes
	{
		const std::array<std::uint8_t, 6> op{ 0xFF, 0x25, 0, 0, 0, 0 };
		std::memcpy(a_at, op.data(), op.size());
		std::memcpy(a_at + op.size(), &a_to, sizeof(a_to));
	}

	std::optional<std::string_view> Hook()
	{
		const auto module = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"Precision.dll"));
		if (!module) {
			return "Precision.dll is not loaded"sv;
		}
		const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(module + reinterpret_cast<const IMAGE_DOS_HEADER*>(module)->e_lfanew);
		if (nt->FileHeader.TimeDateStamp != kTimestamp) {
			return "Precision.dll is not the 2.0.6 build"sv;
		}
		const auto target = module + kRun;
		if (!std::equal(kPrologue.begin(), kPrologue.end(), reinterpret_cast<const std::uint8_t*>(target))) {
			return "PendingHit::Run's first bytes differ"sv;
		}
		// SKSE's trampoline lies near SkyrimSE.exe, out of rel32 reach of Precision.dll: absolute jumps both ways
		auto* stub = static_cast<std::uint8_t*>(VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!stub) {
			return "no memory for the stub"sv;
		}
		// the original: its first four instructions, then a jump back past them
		std::memcpy(stub, kPrologue.data(), kPrologue.size());
		AbsJump(stub + kPrologue.size(), target + kPrologue.size());
		Run = reinterpret_cast<void (*)(PendingHit*)>(stub);
		std::array<std::uint8_t, kPrologue.size()> patch{};
		patch.fill(0x90);  // nop
		AbsJump(patch.data(), reinterpret_cast<std::uintptr_t>(&RunThunk));
		REL::safe_write(target, patch.data(), patch.size());
		return std::nullopt;
	}
}

SKSEPluginInfo(
	.Version = Plugin::VERSION,
	.Name = Plugin::NAME,
	.Author = "Yuof"sv,
	.RuntimeCompatibility = SKSE::VersionIndependence::AddressLibrary)

SKSE_PLUGIN_LOAD(const SKSE::LoadInterface* a_skse)
{
	SKSE::Init(a_skse, { .log = true });
	logger::info("{} v{} on {}"sv, Plugin::NAME, Plugin::VERSION.string(), REL::Module::get().version().string());
	// Precision.dll may load after this plugin: hook once every plugin is loaded
	SKSE::GetMessagingInterface()->RegisterListener([](SKSE::MessagingInterface::Message* a_msg) {
		if (a_msg->type != SKSE::MessagingInterface::kPostLoad) {
			return;
		}
		if (const auto why = Hook()) {
			logger::error("self-check failed ({}): inactive"sv, *why);
		} else {
			logger::info("self-check passed, wrapped Precision 2.0.6 PendingHit::Run"sv);
		}
	});
	return true;
}
