
#include "Plugin.h"

namespace plugin { namespace Reass_TCP { Plugin plugin; } }

using namespace plugin::Reass_TCP;

plugin::Configuration Plugin::Configure()
	{
	plugin::Configuration config;
	config.name = "Reass::TCP";
	config.description = "<Insert description>";
	config.version.major = 0;
	config.version.minor = 1;
	return config;
	}
