
#ifndef BRO_PLUGIN_REASS_TCP
#define BRO_PLUGIN_REASS_TCP

#include <plugin/Plugin.h>

namespace plugin {
namespace Reass_TCP {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
