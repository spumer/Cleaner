#include "extension.h"

#define DEBUG_LOG(...) g_pSmmAPI->ConPrintf(__VA_ARGS__);g_pSmmAPI->ConPrint("\n")
#define TIER0_NAME	SOURCE_BIN_PREFIX "tier0" SOURCE_BIN_SUFFIX SOURCE_BIN_EXT

Cleaner g_Cleaner;
SMEXT_LINK(&g_Cleaner);

CDetour *g_pDetour = 0;
void* pfn_LogDirect = NULL;

char ** g_szStrings;
int g_iStrings = 0;

ISmmAPI *g_pSmmAPI = NULL;

#if SOURCE_ENGINE >= SE_LEFT4DEAD2
DETOUR_DECL_MEMBER4(Detour_LogDirect, LoggingResponse_t, LoggingChannelID_t, channelID, LoggingSeverity_t, severity, Color, color, const char *, pMessage)
{
	for(int i=0;i<g_iStrings;++i)
		if(strstr(pMessage, g_szStrings[i])!=0)
			return LR_CONTINUE;

	if (severity == LS_ASSERT || severity == LS_ERROR) {
		// ASSERT / ERROR can cause process termination
		// We do not needed this, and try to live with undefined behaviour D:
		severity = LS_WARNING;
	}
	return DETOUR_MEMBER_CALL(Detour_LogDirect)(channelID, severity, color, pMessage);
}
#else
// For older Engines
DETOUR_DECL_STATIC2(Detour_DefSpew, SpewRetval_t, SpewType_t, channel, char *, text)
{
	for(int i=0;i<g_iStrings;++i)
		if(strstr(text, g_szStrings[i])!=0)
			return SPEW_CONTINUE;
	return DETOUR_STATIC_CALL(Detour_DefSpew)(channel, text);
}
#endif

void *GetSigAddress(void *pBaseAddr, const char *key)
{
	// Got a symbol here.
	if (key[0] == '@')
		return memutils->ResolveSymbol(pBaseAddr, &key[1]);

	// Convert hex signature to byte pattern
	unsigned char signature[200];
	size_t real_bytes = UTIL_DecodeHexString(signature, sizeof(signature), key);
	if (real_bytes < 1)
		return nullptr;

	// Find that pattern in the pointed module.
	return memutils->FindPattern(pBaseAddr, (char *)signature, real_bytes);
}


bool Cleaner::SDK_OnLoad(char *error, size_t maxlength, bool late)
{
#if SOURCE_ENGINE >= SE_LEFT4DEAD2
	IGameConfig* pGameConfig = NULL;

	if (!gameconfs->LoadGameConfigFile(GAMEDATA_FILE, &pGameConfig, error, maxlength)) {
		snprintf(error, maxlength, "Unable to load a gamedata file \"" GAMEDATA_FILE ".txt\"");
		return false;
	}

	if (!SetupFromGameConfig(pGameConfig, error, maxlength)) {
		gameconfs->CloseGameConfigFile(pGameConfig);
		return false;
	}
	gameconfs->CloseGameConfigFile(pGameConfig);
#endif

	if (!LoadCleanPhrases(error, maxlength)) {
		return false;
	}

	DEBUG_LOG("[CLEANER] Loaded %d phrases to clean", g_iStrings);

	if (!CreateDetours(error, maxlength)) {
		return false;
	}

	g_pDetour->EnableDetour();

	return true;
}

void Cleaner::SDK_OnUnload()
{
	if(g_pDetour) {
		g_pDetour->Destroy();
		g_pDetour = NULL;
	}
	pfn_LogDirect = NULL;

	for(int i = 0; i < g_iStrings; ++i)
	{
		delete [] g_szStrings[i];
	}

	delete [] g_szStrings;
	g_szStrings = NULL;
	g_iStrings = 0;
}

bool Cleaner::SDK_OnMetamodLoad(ISmmAPI *ismm, char *error, size_t maxlen, bool late) {
	g_pSmmAPI = ismm;
	return true;
}

bool Cleaner::SDK_OnMetamodUnload(char *error, size_t maxlength) {
	return true;
}

#ifdef PLATFORM_WINDOWS
inline bool SetupForWindows(IGameConfig* pGameConfig, char* error, int maxlength)
{
	const char* key = "ServerConsolePrintSig_windows";
	const char* symbol = pGameConfig->GetKeyValue(key);
	if (!symbol)
	{
		snprintf(error, maxlength, "Unable to get symbol/pattern for \"%s\" (file: '" GAMEDATA_FILE ".txt')", key);
		return false;
	}

	HMODULE tier0 = GetModuleHandle(TIER0_NAME);
	void* pfn = GetSigAddress(tier0, symbol);
	if (!pfn)
	{
		snprintf(error, maxlength, "Unable to find signature for \"%s\" (file: '" GAMEDATA_FILE ".txt')", key);
		return false;
	}

	int offset = 0;
	pGameConfig->GetOffset("ServerConsolePrint", &offset);
	if (offset != 0) {
		pfn = (void *)((intptr_t)pfn + offset);
	}

	pfn_LogDirect = pfn;
	return true;
}
#elif defined PLATFORM_LINUX
inline bool SetupForLinux(IGameConfig* pGameConfig, char* error, int maxlength)
{
	const char* key = "ServerConsolePrintSig_linux";
	const char* symbol = pGameConfig->GetKeyValue(key);
	if (!symbol)
	{
		snprintf(error, maxlength, "Unable to get symbol/pattern for \"%s\" (file: '" GAMEDATA_FILE ".txt')", key);
		return false;
	}

	void * tier0 = dlopen(TIER0_NAME, RTLD_NOW);
	if (!tier0) {
		snprintf(error, maxlength, "Unable to open dynamic library " TIER0_NAME);
		return false;
	}

	void * pfn = GetSigAddress(tier0, symbol);
	if (!pfn)
	{
		snprintf(error, maxlength, "Unable to find signature for \"%s\" (file: '" GAMEDATA_FILE ".txt')", key);
		dlclose(tier0);
		return false;
	}

	int offset = 0;
	pGameConfig->GetOffset("ServerConsolePrint", &offset);
	if (offset != 0) {
		pfn = (void *)((intptr_t)pfn + offset);
	}

	dlclose(tier0);

	pfn_LogDirect = pfn;
	return true;
}
#else
	#error "Unsupported OS"
#endif

bool Cleaner::SetupFromGameConfig(IGameConfig* pGameConfig, char* error, int maxlength)
{
#ifdef PLATFORM_WINDOWS
	return SetupForWindows(pGameConfig, error, maxlength);
#elif defined PLATFORM_LINUX
	return SetupForLinux(pGameConfig, error, maxlength);
#else
	#error "Unsupported OS"
#endif
}


bool Cleaner::CreateDetours(char* error, size_t maxlength)
{
	// Game config is never used by detour class to handle errors ourselves
	CDetourManager::Init(smutils->GetScriptingEngine(), NULL);

#if SOURCE_ENGINE >= SE_LEFT4DEAD2
	g_pDetour = DETOUR_CREATE_MEMBER(Detour_LogDirect, pfn_LogDirect);
	const char* detour_name = "LogDirect";
#else
	g_pDetour = DETOUR_CREATE_STATIC(Detour_DefSpew, (gpointer)GetSpewOutputFunc());
	const char* detour_name = "DefSpew";
#endif

	if (!g_pDetour)
	{
		snprintf(error, maxlength, "Unable to create a detour for \"%s\"", detour_name);
		return false;
	}

	return true;
}

bool Cleaner::LoadCleanPhrases(char* error, size_t maxlength)
{
	char szPath[256];
	smutils->BuildPath(Path_SM, szPath, sizeof(szPath), "configs/cleaner.cfg");
	FILE * file = fopen(szPath, "r");

	if(file==NULL)
	{
		snprintf(error, maxlength, "Could not read configs/cleaner.cfg.");
		return false;
	}

	int c, lines = 0;
	do
	{
		c = fgetc(file);
		++lines;
	} while (c != EOF);

	rewind(file);

	int len;
	g_szStrings = new char*[lines];

	while(!feof(file))
	{
		g_szStrings[g_iStrings] = new char[256];
		if (fgets(g_szStrings[g_iStrings], 255, file) != NULL)
		{
			len = strlen(g_szStrings[g_iStrings]);
			if(g_szStrings[g_iStrings][len-1]=='\r' || g_szStrings[g_iStrings][len-1]=='\n')
					g_szStrings[g_iStrings][len-1]=0;
			if(g_szStrings[g_iStrings][len-2]=='\r')
					g_szStrings[g_iStrings][len-2]=0;
			++g_iStrings;
		}
	}
	fclose(file);

	if (g_iStrings == 0)
	{
		snprintf(error, maxlength, "No phrases to load. Check configs/cleaner.cfg");
		return false;
	}
	return true;
}

// From SM's stringutil.cpp
size_t UTIL_DecodeHexString(unsigned char *buffer, size_t maxlength, const char *hexstr)
{
	size_t written = 0;
	size_t length = strlen(hexstr);

	for (size_t i = 0; i < length; i++)
	{
		if (written >= maxlength)
			break;
		buffer[written++] = hexstr[i];
		if (hexstr[i] == '\\' && hexstr[i + 1] == 'x')
		{
			if (i + 3 >= length)
				continue;
			/* Get the hex part. */
			char s_byte[3];
			int r_byte;
			s_byte[0] = hexstr[i + 2];
			s_byte[1] = hexstr[i + 3];
			s_byte[2] = '\0';
			/* Read it as an integer */
			sscanf(s_byte, "%x", &r_byte);
			/* Save the value */
			buffer[written - 1] = r_byte;
			/* Adjust index */
			i += 3;
		}
	}

	return written;
}