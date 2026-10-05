-- ==========================================================
-- iOS Network License & Dylib Injection Framework
-- 数据库初始化脚本 (MySQL 8.0+ / MariaDB)
-- ==========================================================

CREATE DATABASE IF NOT EXISTS `ios_auth_db` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `ios_auth_db`;

-- 1. 卡密主表
CREATE TABLE IF NOT EXISTS `cards` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `card_key` VARCHAR(64) NOT NULL COMMENT '卡密激活码(唯一)',
  `card_type` VARCHAR(20) NOT NULL DEFAULT 'DAILY' COMMENT '卡密类型: HOURLY/DAILY/WEEKLY/MONTHLY/ANNUAL/LIFETIME',
  `status` VARCHAR(20) NOT NULL DEFAULT 'UNACTIVATED' COMMENT '状态: UNACTIVATED/ACTIVE/EXPIRED/FROZEN',
  `max_devices` INT UNSIGNED NOT NULL DEFAULT 1 COMMENT '最大绑定设备数',
  `unbind_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '已解绑次数',
  `max_unbind_limit` INT UNSIGNED NOT NULL DEFAULT 3 COMMENT '最大允许解绑次数',
  `activated_at` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '首次激活Unix秒时间戳',
  `expire_at` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '过期截止Unix秒时间戳 (0为永久)',
  `note` VARCHAR(255) DEFAULT '' COMMENT '管理员备注',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_card_key` (`card_key`),
  KEY `idx_status_expire` (`status`, `expire_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='卡密主表';

-- 2. 卡密-设备绑定关系表
CREATE TABLE IF NOT EXISTS `card_bindings` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `card_key` VARCHAR(64) NOT NULL COMMENT '关联卡密',
  `device_fp_hash` VARCHAR(64) NOT NULL COMMENT '设备指纹复合SHA256哈希',
  `keychain_uuid` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '设备Keychain持久化UUID',
  `device_model` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '设备硬件型号(如iPhone14,2)',
  `system_version` VARCHAR(32) NOT NULL DEFAULT '' COMMENT 'iOS系统版本',
  `first_bound_at` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '首次绑定时间戳',
  `last_seen_at` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '最后活跃心跳时间戳',
  `last_ip` VARCHAR(45) NOT NULL DEFAULT '' COMMENT '最后活跃IP地址',
  `is_active` TINYINT UNSIGNED NOT NULL DEFAULT 1 COMMENT '是否有效绑定(1有效 0已解绑)',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`),
  KEY `idx_card_active` (`card_key`, `is_active`),
  KEY `idx_device_hash` (`device_fp_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='设备绑定关系表';

-- 3. 安全审计与操作日志表
CREATE TABLE IF NOT EXISTS `audit_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `action_type` VARCHAR(32) NOT NULL COMMENT '操作类型: HANDSHAKE/ACTIVATE/VERIFY/HEARTBEAT/UNBIND/TAMPER/ADMIN',
  `card_key` VARCHAR(64) DEFAULT NULL COMMENT '关联卡密',
  `client_ip` VARCHAR(45) NOT NULL DEFAULT '' COMMENT '客户端来源IP',
  `device_info` TEXT COMMENT '设备信息JSON',
  `payload_summary` VARCHAR(500) NOT NULL DEFAULT '' COMMENT '事件说明摘要',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`),
  KEY `idx_action_card` (`action_type`, `card_key`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='安全审计日志表';
