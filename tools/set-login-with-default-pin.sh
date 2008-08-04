#!/bin/bash
#                                                              -*- sh -*-
# set-login-with-default-bin.sh
#	Copyright (C) 2008 g10 Code GmbH
#
# This file is part of Poldi.
#
# Poldi is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# Poldi is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

program_name="set-login-with-default-pin.sh"

if [ "$#" != "1" ]; then
    echo "Usage: ${program_name} <login data>" >&2
    exit 1
fi

logindata="$1"
logindata_final=$(echo -ne "${logindata}" | sed -e 's/+/%2b/;' | sed -e 's/ /+/;')
logindata_final="${logindata_final}%0a%14F=3%18"

#echo "'$logindata_final'"
echo "SCD SETATTR LOGIN-DATA ${logindata_final}" | gpg-connect-agent

exit 0
