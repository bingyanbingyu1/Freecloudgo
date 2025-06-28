#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FreeCloud VPS 自动续费脚本
支持单个账号和批量账号续费
"""

import os
import sys
import json
import time
import argparse
import logging
from typing import Dict, List, Any
from urllib.parse import urlencode

try:
    import cloudscraper
except ImportError:
    logging.error("请安装 cloudscraper: pip install cloudscraper")
    sys.exit(1)

# 配置常量
LOGIN_URL = "https://freecloud.ltd/login"
CONSOLE_URL = "https://freecloud.ltd/member/index"
RENEW_URL = "https://freecloud.ltd/server/detail/{}/renew"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Referer": "https://freecloud.ltd/login",
    "Origin": "https://freecloud.ltd",
}

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class FreeCloudRenewer:
    """FreeCloud VPS 续费器"""

    def __init__(self):
        self.scraper = cloudscraper.create_scraper()

    def login(self, username: str, password: str) -> bool:
        # 用户登录
        logger.info(f"正在登录用户: {username}")

        payload = {
            "username": username,
            "password": password,
            "mobile": "",
            "captcha": "",
            "verify_code": "",
            "agree": "1",
            "login_type": "PASS",
            "submit": "1"
        }

        response = self.scraper.post(LOGIN_URL, data=payload, headers=HEADERS)

        if response.status_code != 200:
            logger.error(f"登录请求失败，状态码: {response.status_code}")
            return False

        # 检查登录状态
        if "退出登录" not in response.text and "member/index" not in response.text:
            logger.error("登录失败，请检查用户名和密码")
            return False

        # 验证会话
        check_response = self.scraper.get(CONSOLE_URL)
        if check_response.status_code != 200:
            logger.error("会话验证失败")
            return False

        logger.info("登录成功")
        return True

    def renew_machine(self, machine_id: int) -> bool:
        """续费指定机器"""
        logger.info(f"正在续费机器: {machine_id}")

        data = {
            "month": "1",
            "submit": "1",
            "coupon_id": "0"
        }

        url = RENEW_URL.format(machine_id)
        response = self.scraper.post(url, data=data, headers=HEADERS)

        if response.status_code != 200:
            logger.error(f"机器 {machine_id} 续费请求失败，状态码: {response.status_code}")
            return False

        # 解析响应
        try:
            resp_json = response.json()
            msg = resp_json.get("msg", "")
        except json.JSONDecodeError:
            msg = response.text

        if "请在到期前3天后再续费" in msg:
            logger.warning(f"机器 {machine_id}: {msg}")
            return True
        elif "续费成功" in msg:
            logger.info(f"机器 {machine_id}: {msg}")
            return True
        else:
            logger.error(f"机器 {machine_id} 续费失败: {msg}")
            return False

    def process_profile(self, profile: Dict[str, Any]) -> bool:
        """处理单个用户配置"""
        username = profile.get("username")
        password = profile.get("password")
        machines = profile.get("machines", [])

        if not username or not password:
            logger.error("用户名或密码为空，跳过此配置")
            return False

        if not machines:
            logger.warning(f"用户 {username} 没有配置机器列表")
            return True

        # 登录
        if not self.login(username, password):
            logger.error(f"用户 {username} 登录失败")
            return False

        # 续费所有机器
        success_count = 0
        for machine_id in machines:
            if self.renew_machine(machine_id):
                success_count += 1
            time.sleep(1)  # 避免请求过于频繁

        logger.info(f"用户 {username} 完成续费，成功: {success_count}/{len(machines)}")
        return success_count == len(machines)


def parse_arguments() -> argparse.Namespace:
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="FreeCloud VPS 自动续费脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""使用示例:
        单个账号续费:
            python renew.py -c '{"username":"user0","password":"pass0","machines":[100,200]}'

        批量续费（从环境变量）:
            python renew.py
        """
    )

    parser.add_argument(
        "-c", "--config",
        type=str,
        help="单个账号的JSON配置字符串"
    )

    return parser.parse_args()


def load_profiles_from_env() -> List[Dict[str, Any]]:
    """从环境变量加载配置"""
    config = os.getenv("FC_PROFILES")
    if not config:
        logger.error("环境变量 FC_PROFILES 未设置")
        sys.exit(1)

    try:
        profiles = json.loads(config)
    except json.JSONDecodeError as e:
        logger.error(f"解析 FC_PROFILES 失败: {e}")
        sys.exit(1)

    # 确保返回列表格式
    if isinstance(profiles, dict):
        profiles = [profiles]
    elif not isinstance(profiles, list):
        logger.error("FC_PROFILES 格式错误，应为JSON对象或数组")
        sys.exit(1)

    return profiles


def load_profile_from_arg(config_str: str) -> Dict[str, Any]:
    """从命令行参数加载配置"""
    try:
        profile = json.loads(config_str)
    except json.JSONDecodeError as e:
        logger.error(f"解析配置参数失败: {e}")
        sys.exit(1)

    if not isinstance(profile, dict):
        logger.error("配置参数应为JSON对象")
        sys.exit(1)

    return profile


def validate_profile(profile: Dict[str, Any]) -> bool:
    """验证配置格式"""
    required_fields = ["username", "password"]
    for field in required_fields:
        if not profile.get(field):
            logger.error(f"配置缺少必需字段: {field}")
            return False

    machines = profile.get("machines", [])
    if not isinstance(machines, list):
        logger.error("machines 字段应为数组")
        return False

    return True


def main():
    """主函数"""
    args = parse_arguments()

    # 加载配置
    if args.config:
        # 单个账号模式
        profile = load_profile_from_arg(args.config)
        if not validate_profile(profile):
            sys.exit(1)
        profiles = [profile]
    else:
        # 批量模式
        profiles = load_profiles_from_env()

    if not profiles:
        logger.error("没有找到有效的配置")
        sys.exit(1)

    logger.info(f"开始处理 {len(profiles)} 个账号配置")

    # 处理所有配置
    renewer = FreeCloudRenewer()
    success_count = 0

    for i, profile in enumerate(profiles, 1):
        logger.info(f"处理第 {i}/{len(profiles)} 个配置")

        if not validate_profile(profile):
            logger.error(f"第 {i} 个配置格式错误，跳过")
            continue

        if renewer.process_profile(profile):
            success_count += 1

        # 账号间间隔
        if i < len(profiles):
            time.sleep(2)

    logger.info(f"处理完成，成功: {success_count}/{len(profiles)}")

    if success_count < len(profiles):
        logger.error("部分账号处理失败")
        sys.exit(1)

    logger.info("所有账号处理成功")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("用户中断操作")
        sys.exit(1)
    except Exception as e:
        logger.error(f"程序执行出错: {e}")
        sys.exit(1)
