#!/usr/bin/env python3



import os
import pymysql
import re
import datetime
import yaml
import socket
import time
import sys
from collections import defaultdict

config_file = os.path.join('/usr/local/src/analysislog/config.yml')
with open(config_file) as f:
	config_data = yaml.load(f)


def DB(sql,func="select"):
	#数据库操作方法
	db_name = config_data['db']['name']
	db_port = int(config_data['db']['port'])
	db_host = config_data['db']['host']
	db_user = config_data['db']['user']
	db_pass = config_data['db']['passwd']

	conn = pymysql.connect(
		host = db_host,
		port = db_port,
		user = db_user,
		passwd = db_pass,
		db = db_name
	)
	cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)
	if func == "insert":
		try:
			cursor.execute(sql)
			conn.commit()
			conn.close()
			return True
		except:
			conn.rollback()
			conn.close()
			return False
	elif func == "select":
		try:
			cursor.execute(sql)
			results = cursor.fetchall()
			conn.close()
			return results
		except:
			conn.close()
			return False



def getLocalIP():
	'''
	获取本机IP地址
	:return:
	'''
	hostname = socket.gethostname()
	ipList = socket.gethostbyname_ex(hostname)
	try:
		ip = ipList[-1][-1]
		return ip
	except:
		err = "获取IP地址错误"
		SaveLog(err,2)
	return config_data['global']['ipaddr']

def SaveLog(data,type=1):
	'''
	记录日志
	:param data:
	:param type: 1 INFO 2 ERROR 3 WARRING
	:return:
	'''
	time_stm = "[%s]  " % datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	data = str(data)
	type = int(type)
	if type == 1:
		data = time_stm + " [INFO] " + data + "\n"
	elif type == 2:
		data = time_stm + " [ERROR] " + data + "\n"
	else:
		data = time_stm + " [WARNNING] " + data + "\n"

	log_file = config_data['log']['path']
	with open(log_file,'a') as f:
		f.write(data)



def getLogFileName():
	'''
	获取要分析日志文件名称
	:return:
	'''
	log_file = os.path.join(config_data['global']['path'],config_data['global']['name'])
	cmp = re.compile(r'(?P<path>.*com_)(?P<stm>.*)(?P<tag>.log)')
	try:                                                            # 获取上一分钟日志文件名称
		filename_dict = cmp.match(log_file).groupdict()
		last_log_time = (datetime.datetime.now() - datetime.timedelta(minutes=2)).strftime(filename_dict['stm'])        # 计算上一分钟具体时间
		filename = filename_dict['path'] + str(last_log_time) + filename_dict['tag']
		return filename
	except:
		err = "获取日志文件名错误"
		SaveLog(err,2)
	return False

def getLogData():
	log_detail_dict = {}              # 日志详细字典
	logfile_name = getLogFileName()                             # 获取日志文件名
	if not os.path.exists(logfile_name):
		print("%s not exist!" % logfile_name)
		return False
	if not logfile_name:
		return False

	####  access log 统计
	field_separator = config_data['global']['separator']        # 获取日志分隔符
	with open(logfile_name) as f:                               # 读取日志文件内容 存入到log_data
		log_data = f.readlines()

	for each_log in log_data:
		each_log = each_log.split(field_separator)              # 分隔日志
		time_tag = each_log[2].split()[0]                       # 获取日志时间戳
		time_tag = time.strftime("%Y/%m/%d %H:%M:%S",time.strptime(time_tag,'%d/%b/%Y:%H:%M:%S'))
		time_min_tag = time.strftime("%Y/%m/%d %H:%M:00",time.strptime(time_tag,'%Y/%m/%d %H:%M:%S'))
		log_detail_dict.setdefault(time_tag,{})                 # {29/Jan/2018:11:41:48} 2018/01/29 14:54:04
		if 'filename' not in log_detail_dict[time_tag]:
			log_detail_dict[time_tag]['filename'] = {}
		log_detail_dict[time_tag]['filename'][each_log[3]] = log_detail_dict[time_tag]['filename'].setdefault(each_log[3],0) + 1    # 请求文件

		if 'servername' not in log_detail_dict[time_tag]:
			log_detail_dict[time_tag]['servername'] = {}
		log_detail_dict[time_tag]['servername'][each_log[4]] = log_detail_dict[time_tag]['servername'].setdefault(each_log[4],0) + 1    # 请求域名

		if 'status' not in log_detail_dict[time_tag]:
			log_detail_dict[time_tag]['status'] = {}
		log_detail_dict[time_tag]['status'][each_log[5]] = log_detail_dict[time_tag]['status'].setdefault(each_log[5],0) + 1    # 状态码

		if 'ip' not in log_detail_dict[time_tag]:    # 用户IP
			log_detail_dict[time_tag]['ip'] = []
		log_detail_dict[time_tag]['ip'].append(each_log[9])

		if 'request' not in log_detail_dict[time_tag]:log_detail_dict[time_tag]['request'] = []     # 请求时间
		log_detail_dict[time_tag]['request'].append(each_log[10])

		if 'response' not in log_detail_dict[time_tag]:log_detail_dict[time_tag]['response'] = []   # 相应时间
		log_detail_dict[time_tag]['response'].append(each_log[11])


	return (time_min_tag,log_detail_dict)

def updateDB():
	local_ip = getLocalIP()
	try:
		(time_min_tag,log_detail_dict) = getLogData()
	except:
		time_min_tag = (datetime.datetime.now() - datetime.timedelta(minutes=2)).strftime("%Y/%m/%d %H:%M:00")
		info_sql = "INSERT INTO app_loginfo(host_ip,check_time,status_200," \
	           "status_204,status_404,status_502,ip_nums,max_qps,min_qps," \
	           "max_qps_time,min_qps_time,min_request_times,max_request_times," \
	           "max_qps_time,min_qps_time,min_request_times,max_request_times," \
	           "min_response_times,max_response_times,all_requests,all_status_200) VALUES " \
	           "('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')" % (
		local_ip,time_min_tag,'0','0','0','0','0','0','0',
		time_min_tag,time_min_tag,'0','0','0','0','0','0')
		DB(info_sql,'insert')
		return False

	max_request_time = 0
	min_request_time = 10
	max_response_time = 0
	min_response_time = 10
	min_qps = 0
	max_qps = 0
	max_200 = 0
	max_204 = 0
	max_4xx = 0
	max_qps_time = ''
	min_qps_time = ''
	max_ip = 0
	max_502 = 0

	all_request = 0
	all_status_200 = 0


	for k,v in log_detail_dict.items():
		status_num = 0
		for status in log_detail_dict[k]['status'].keys():
			all_request += log_detail_dict[k]['status'][status]
			status_num += log_detail_dict[k]['status'][status]
			if 	status.startswith('4'):
				if max_4xx < log_detail_dict[k]['status'][status]:
					max_4xx = log_detail_dict[k]['status'][status]
			if status.startswith('502'):
				if max_502 < log_detail_dict[k]['status'][status]:
					max_502 = log_detail_dict[k]['status'][status]
			if status.startswith('200'):
				all_status_200 += log_detail_dict[k]['status'][status]
				if max_200 < log_detail_dict[k]['status'][status]:
					max_200 = log_detail_dict[k]['status'][status]
			if status.startswith('204'):
				if max_204 < log_detail_dict[k]['status'][status]:
					max_204 = log_detail_dict[k]['status'][status]

		for req_time in v['request']:
			try:
				req_time = float(req_time)
				if req_time > max_request_time:
					max_request_time = req_time
				if req_time < min_request_time:
					min_request_time = req_time
			except:
				pass
		for res_time in v['response']:
			try:
				res_time = float(res_time)
				if res_time > max_response_time:
					max_response_time = res_time
				if res_time < min_response_time:
					min_response_time = res_time
			except:
				pass


		if min_qps == 0:
			min_qps = status_num
		if min_qps > status_num:
			min_qps = status_num
			min_qps_time = k

		if max_qps < status_num:
			max_qps = status_num
			max_qps_time = k


		if max_ip < len(v['ip']):
			max_ip = len(v['ip'])


	# sql = "INSERT INTO app_loginfo(time_tag,max_200,max_204,status_404,status_502,ip, " \
	# 		"min_request_time,max_request_time,min_response_time," \
	#         "max_response_time,max_qps,min_qps,max_qps_time,min_qps_time,local_ip) VALUES " \
	# 	    "('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')" % (time_min_tag,
	#                                                                     max_200,max_204,max_4xx,max_502,max_ip,
	# 	                                                                min_request_time,max_request_time,
	# 	                                                                min_response_time,min_response_time,
     #                                                                  max_qps,min_qps,max_qps_time,min_qps_time,local_ip)

	info_sql = "INSERT INTO app_loginfo(host_ip,check_time,status_200," \
	           "status_204,status_404,status_502,ip_nums,max_qps,min_qps," \
	           "max_qps_time,min_qps_time,min_request_times,max_request_times," \
	           "min_response_times,max_response_times,all_requests,all_status_200) VALUES " \
	           "('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')" % (
		local_ip,time_min_tag,max_200,max_204,max_4xx,max_502,max_ip,max_qps,min_qps,
		max_qps_time,min_qps_time,min_request_time,max_request_time,min_response_time,max_response_time,all_request,all_status_200
	)

	DB(info_sql,'insert')
	# print(info_sql)



if __name__ == '__main__':
	updateDB()
	logfile_name = getLogFileName()
	os.system('rm -f %s' % logfile_name)
