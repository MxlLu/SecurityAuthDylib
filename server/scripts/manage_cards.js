#!/usr/bin/env node

/**
 * 卡密与业务参数本地 CLI 运维管理工具
 * 使用示例:
 *   node scripts/manage_cards.js create --key VIP-2026-8888 --type MONTHLY --devices 2 --note "内部测试"
 *   node scripts/manage_cards.js batch --count 5 --type DAILY --prefix PRO
 *   node scripts/manage_cards.js list
 *   node scripts/manage_cards.js reset --key VIP-2026-8888
 *   node scripts/manage_cards.js freeze --key VIP-2026-8888
 *   node scripts/manage_cards.js delete --key VIP-2026-8888
 *   node scripts/manage_cards.js config
 */

import { initStore } from '../src/storage/json-store.js';
import { adminService } from '../src/services/admin-service.js';

function parseArgs() {
  const args = process.argv.slice(2);
  const command = args[0] || 'help';
  const options = {};

  for (let i = 1; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const key = args[i].slice(2);
      const val = args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : true;
      options[key] = val;
      if (val !== true) i++;
    }
  }

  return { command, options };
}

function printUsage() {
  console.log(`
============================================================
       iOS Auth Server - 卡密与业务参数管理工具
============================================================
命令列表:
  create        创建单张自定义卡密
                参数: --key <卡密字符串> [--type DAILY/MONTHLY/...] [--devices 1] [--unbind 3] [--seconds 0] [--note 备注]

  batch         批量随机生成卡密
                参数: --count 10 [--type DAILY] [--prefix VIP] [--devices 1] [--note 备注]

  list          查看所有卡密及当前设备绑定情况

  get           查看指定卡密详细信息
                参数: --key <卡密字符串>

  freeze        冻结指定卡密
                参数: --key <卡密字符串>

  unfreeze      解冻指定卡密
                参数: --key <卡密字符串>

  reset         强制解绑/清空卡密的所有设备
                参数: --key <卡密字符串>

  delete        永久删除指定卡密
                参数: --key <卡密字符串>

  config        查看系统当前全局业务参数

  set-config    修改业务参数
                参数: [--heartbeat 60] [--deduct 2] [--announcement "内容"]
============================================================
`);
}

async function main() {
  initStore();
  const { command, options } = parseArgs();

  switch (command) {
    case 'create': {
      if (!options.key) {
        console.error('[Error] 请提供 --key 参数，例如: --key VIP-2026-8888');
        process.exit(1);
      }
      try {
        const res = adminService.generateCards({
          custom_card_key: options.key,
          card_type: options.type || 'DAILY',
          max_devices: options.devices ? parseInt(options.devices, 10) : 1,
          max_unbind_limit: options.unbind ? parseInt(options.unbind, 10) : 3,
          custom_duration_seconds: options.seconds ? parseInt(options.seconds, 10) : 0,
          note: options.note || ''
        });
        console.log('[OK] 自定义卡密创建成功:');
        console.table(res);
      } catch (err) {
        console.error('[Error]', err.msg || err.message);
      }
      break;
    }

    case 'batch': {
      const count = options.count ? parseInt(options.count, 10) : 5;
      const res = adminService.generateCards({
        count,
        card_type: options.type || 'DAILY',
        prefix: options.prefix || 'VIP',
        max_devices: options.devices ? parseInt(options.devices, 10) : 1,
        note: options.note || ''
      });
      console.log(`[OK] 批量生成卡密 ${res.length} 张:`);
      console.table(res.map(c => ({
        卡密: c.card_key,
        套餐: c.card_type,
        最大设备: c.max_devices,
        状态: c.status
      })));
      break;
    }

    case 'list': {
      const list = adminService.listCards();
      console.log(`[+] 当前总计卡密数: ${list.length}`);
      console.table(list.map(c => ({
        卡密: c.card_key,
        类型: c.card_type,
        状态: c.status,
        已绑设备数: c.active_bindings ? c.active_bindings.length : 0,
        最大设备: c.max_devices,
        解绑次数: `${c.unbind_count}/${c.max_unbind_limit}`,
        到期时间: c.expire_at === 0 ? (c.status === 'ACTIVE' ? '永久' : '未激活') : new Date(c.expire_at * 1000).toLocaleString(),
        备注: c.note
      })));
      break;
    }

    case 'get': {
      if (!options.key) {
        console.error('[Error] 请提供 --key 参数');
        process.exit(1);
      }
      try {
        const card = adminService.getCard(options.key);
        console.log(JSON.stringify(card, null, 2));
      } catch (err) {
        console.error('[Error]', err.msg || err.message);
      }
      break;
    }

    case 'freeze': {
      if (!options.key) {
        console.error('[Error] 请提供 --key 参数');
        process.exit(1);
      }
      adminService.updateCardStatus(options.key, 'FROZEN');
      console.log(`[OK] 卡密 ${options.key} 已冻结`);
      break;
    }

    case 'unfreeze': {
      if (!options.key) {
        console.error('[Error] 请提供 --key 参数');
        process.exit(1);
      }
      adminService.updateCardStatus(options.key, 'ACTIVE');
      console.log(`[OK] 卡密 ${options.key} 已解冻为 ACTIVE`);
      break;
    }

    case 'reset': {
      if (!options.key) {
        console.error('[Error] 请提供 --key 参数');
        process.exit(1);
      }
      const res = adminService.resetBindings(options.key);
      console.log(`[OK] 卡密 ${options.key} 绑定已重置 (解绑 ${res.count} 台设备)`);
      break;
    }

    case 'delete': {
      if (!options.key) {
        console.error('[Error] 请提供 --key 参数');
        process.exit(1);
      }
      adminService.deleteCard(options.key);
      console.log(`[OK] 卡密 ${options.key} 已永久删除`);
      break;
    }

    case 'config': {
      const cfg = adminService.getConfig();
      console.log(JSON.stringify(cfg, null, 2));
      break;
    }

    case 'set-config': {
      const updates = { business: {}, security: {} };
      if (options.heartbeat) updates.security.heartbeat_interval_sec = parseInt(options.heartbeat, 10);
      if (options.deduct) updates.business.unbind_deduct_hours = parseInt(options.deduct, 10);
      if (options.announcement) updates.business.announcement = {
        id: Date.now(),
        title: '系统通知',
        content: options.announcement,
        force_alert: options.force === true || options.force === 'true'
      };
      const res = adminService.updateConfig(updates);
      console.log('[OK] 业务参数更新成功:', JSON.stringify(res, null, 2));
      break;
    }

    default:
      printUsage();
      break;
  }
}

main().catch(err => {
  console.error('[Fatal Error]', err);
  process.exit(1);
});
