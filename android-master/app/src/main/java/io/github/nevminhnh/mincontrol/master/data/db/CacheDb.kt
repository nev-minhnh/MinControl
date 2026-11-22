package io.github.nevminhnh.mincontrol.master.data.db

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Transaction
import kotlinx.coroutines.flow.Flow

/** Offline cache. Rows keep the server JSON so the UI can be rebuilt without a network. */
@Entity(tableName = "devices")
data class DeviceRow(@PrimaryKey val deviceId: String, val json: String, val fetchedAt: Long)

@Entity(tableName = "alerts")
data class AlertRow(
    @PrimaryKey val id: String,
    val deviceId: String,
    val userSid: String?,
    val ts: String,
    val type: String,
    val severity: String,
    val json: String,
    val acked: Boolean = false,
)

@Entity(tableName = "web", primaryKeys = ["deviceId", "userSid", "ts", "url"])
data class WebRow(
    val deviceId: String,
    val userSid: String,
    val ts: String,
    val url: String,
    val kind: String,
    val host: String?,
    val title: String?,
    val durationSec: Int?,
    val category: String?,
)

@Entity(tableName = "policies")
data class PolicyRow(@PrimaryKey val deviceId: String, val version: Int, val seq: Long, val envelopeJson: String)

@Dao
interface CacheDao {
    @Query("SELECT * FROM devices") fun devicesFlow(): Flow<List<DeviceRow>>
    @Query("SELECT * FROM devices") suspend fun devices(): List<DeviceRow>
    @Query("DELETE FROM devices") suspend fun clearDevices()
    @Insert(onConflict = OnConflictStrategy.REPLACE) suspend fun putDevices(rows: List<DeviceRow>)

    @Transaction
    suspend fun replaceDevices(rows: List<DeviceRow>) { clearDevices(); putDevices(rows) }

    @Query("SELECT * FROM alerts ORDER BY ts DESC LIMIT 300") fun alertsFlow(): Flow<List<AlertRow>>
    @Insert(onConflict = OnConflictStrategy.REPLACE) suspend fun putAlerts(rows: List<AlertRow>)
    @Query("SELECT id FROM alerts WHERE acked = 1") suspend fun ackedIds(): List<String>
    @Query("UPDATE alerts SET acked = 1 WHERE id = :id") suspend fun markAcked(id: String)

    @Query(
        """SELECT * FROM web WHERE deviceId = :deviceId AND userSid = :userSid AND ts >= :from AND ts < :to
           AND (:kind IS NULL OR kind = :kind)
           AND (:q IS NULL OR url LIKE '%' || :q || '%' OR title LIKE '%' || :q || '%')
           ORDER BY ts DESC LIMIT :limit"""
    )
    suspend fun web(deviceId: String, userSid: String, from: String, to: String, kind: String?, q: String?, limit: Int): List<WebRow>
    @Insert(onConflict = OnConflictStrategy.REPLACE) suspend fun putWeb(rows: List<WebRow>)

    @Query("SELECT * FROM policies WHERE deviceId = :deviceId") suspend fun policy(deviceId: String): PolicyRow?
    @Insert(onConflict = OnConflictStrategy.REPLACE) suspend fun putPolicy(row: PolicyRow)
}

@Database(entities = [DeviceRow::class, AlertRow::class, WebRow::class, PolicyRow::class], version = 1, exportSchema = false)
abstract class CacheDb : RoomDatabase() {
    abstract fun dao(): CacheDao

    companion object {
        fun create(context: Context): CacheDb =
            Room.databaseBuilder(context, CacheDb::class.java, "mincontrol-cache.db")
                .fallbackToDestructiveMigration(dropAllTables = true)
                .build()
    }
}
