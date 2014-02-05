# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# this is used/needed by the APACHE2 build system
#
mod_fcgid.la: mod_fcgid.slo fcgid_bridge.slo fcgid_conf.slo fcgid_pm_main.slo fcgid_protocol.slo fcgid_spawn_ctl.slo  fcgid_proctbl_unix.slo fcgid_pm_unix.slo fcgid_proc_unix.slo fcgid_bucket.slo fcgid_filter.slo fcgid_mutex_unix.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version mod_fcgid.lo fcgid_bridge.lo fcgid_conf.lo fcgid_pm_main.lo fcgid_protocol.lo fcgid_spawn_ctl.lo  fcgid_proctbl_unix.lo fcgid_pm_unix.lo fcgid_proc_unix.lo fcgid_bucket.lo fcgid_filter.lo fcgid_mutex_unix.lo
DISTCLEAN_TARGETS = modules.mk
static =
shared =  mod_fcgid.la

