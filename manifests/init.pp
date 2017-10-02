# cisecurity
#
# Metaclass to configure with all Level 1 and Level 2 controls enabled.

class cisecurity {

  include "cisecurity::filesystem"
  include "cisecurity::services"
  include "cisecurity::packages"
  include "cisecurity::security"
  include "cisecurity::pam"
  include "cisecurity::network"

}
