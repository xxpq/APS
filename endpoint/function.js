// ------ 用户登录 --------

function main() {
    if (!payload.get().headers['User-Agent']) {
        return errMsg(413, '参数错误');
    }

    let uaInfo = ex.parseUserAgent(payload.get().headers['User-Agent'][0]);
    let ipAddr = payload.get().remote_addr.split(':')[0]

    const data = payload.get().body?.toObject();
    // 校验验证码
    // if (!captcha.verify(data.captchaId, data.captcha)) {
    //     return errMsg(511, '验证码错误');
    // }

    let errorTime = cache.get('login', ipAddr)
    let userErrorTime = cache.get('login', data.username)
    errorTime = userErrorTime > errorTime ? userErrorTime : errorTime
    // 用户密码错误3次，封禁IP地址和用户名
    if (errorTime > 3) {
        return errMsg(403, '登录失败次数过多，请稍后再试');
    }

    let loginType = 'username'

    if (data.username.match(/^\d+$/)) {
        loginType = 'phone'
    }

    // 查找用户表
    const res = SQL.query('system_sql', `SELECT * FROM sys_users WHERE ${loginType} = ?`, data.username);

    if (!res || !res.length) {
        cache.set('login', data.username, errorTime + 1, 180 * 1000)
        cache.set('login', ipAddr, errorTime + 1, 180 * 1000)
        return errMsg(511, '用户或密码不正确');
    }
    const userData = res[0];
    // 校验密码
    if (!crypto.bcrypt.diff(data.password, userData.password)) {
        cache.set('login', data.username, errorTime + 1, 1800)
        cache.set('login', ipAddr, errorTime + 1, 1800 * 1000)
        log(uaInfo, userData, ipAddr, 1)
        return errMsg(511, '用户或密码不正确');
    }

    // 登录成功，清除错误次数
    // cache.del('login', data.username)

    // 根据角色id获取key
    // const roleRes = SQL.query('system_sql', 'SELECT role_key FROM sys_roles WHERE role_id = ?', userData.role_id);

    // 生成Token / 7天后过期
    const sevenDays = parseInt((new Date().getTime() + 1000 * 60 * 60 * 24 * 7) / 1000);

    let token = jwt_issue(userData.user_id, userData.nickname);
    // 更新最后登录时间和IP
    SQL.push('system_sql', 'UPDATE sys_users SET last_login_time = NOW(),last_login_ip = ? WHERE user_id =?', ipAddr, userData.user_id);
    // 记录登录日志
    log(uaInfo, userData, ipAddr, 0)
    // response.headers.set('Authorization', 'Bearer ' + token)
    response.cookies.setRaw(`token=${token}; Path=/; Max-Age=604800;`)
    // return okMsg({ expire: sevenDays, token: token, userId: userData.user_id });
    return okMsg({ expire: sevenDays, userId: userData.user_id,token });
}

// expire: 1714754886;
// token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VySWQiOjEsIlRlbmFudElkIjowLCJPcmdhbml6YXRpb25JZCI6MiwiVXNlck5hbWUiOiJyb290IiwiUm9sZUlkIjoxLCJSb2xlS2V5IjoiYWRtaW4iLCJEZXB0SWQiOjAsIlBvc3RJZCI6MSwiZXhwIjoxNzE0NzU0ODg2LCJpc3MiOiJ4TWFnaWMiLCJuYmYiOjE3MTQxNDkwODZ9.ZRidybNoZWKhUXkCeqZHtixO_oyzG56ZFtRKHPSU4lc';

// captcha: '1604';
// captchaId: 'BgsXvVYOUAD8dfKUfs2f';
// password: '123456';
// username: 'root';


function log(uaInfo, USER_INFO, addr, status) {
    if (addr == null) {
        return
    }

    // 记录登录日志
    SQL.push('system_sql', 'INSERT INTO log_logins (info_id, user_id, username, status, ipaddr, login_location, browser, os, platform, ua) VALUES (?,?,?,?,?,?,?,?,?,?)',
        ex.suid().base58(),
        USER_INFO.user_id,
        USER_INFO.username,
        status,
        addr,
        '未知',
        uaInfo.browser,
        uaInfo.os,
        uaInfo.deviceModel,
        payload.get().headers['User-Agent'][0],
    );
}