@load base/protocols/ssh
@load base/frameworks/notice
@load base/frameworks/sumstats

module SSH;

export {
    redef enum Notice::Type += {
        Exceeded_Failed_Login_Threshold,
        Attacker_Detected,
    };

    const failed_login_threshold: count = 5 &redef;
}

global failed_logins: table[addr] of count = table();
global attackers: set[addr] = set();
global detected_attackers: set[addr] = set();

event ssh_auth_failed(c: connection)
    {
    local id = c$id$orig_h;

    if (id !in failed_logins) {
        failed_logins[id] = 1;
    } else {
        failed_logins[id] += 1;
	}
        if (failed_logins[id] <= failed_login_threshold) {
            print fmt(""Name: Yug, Roll No.: CS23MTECH14019, Connection UID %s: Host %s has attempted failed login (%d time).", c$uid, id, failed_logins[id]);
        }
    

    if (failed_logins[id] > failed_login_threshold && !(id in detected_attackers)) {
        print fmt(""Name: Yug, Roll No.: CS23MTECH14019, Connection UID %s: Host %s has exceeded the failed login threshold (%d times) and is classified as an attacker.", c$uid, id, failed_logins[id]);
        attackers += {id};
        detected_attackers += {id};
        NOTICE([$note=Exceeded_Failed_Login_Threshold,
                $msg=fmt("Connection UID %s: Host %s has exceeded the failed login threshold (%d times) and is classified as an attacker.", c$uid, id, failed_logins[id]),
                $src=id]);
        NOTICE([$note=Attacker_Detected,
                $msg=fmt("Host %s has been classified as an attacker.", id),
                $src=id]);
    }
}

